//! How the vault store talks to 1Password: the item requests it makes
//! (`Op`), and `Opcore`, opcore's Client that answers them, signed in on the
//! first request only. The tests answer them in memory (`Memory`).
use opcore::core::{Core, Wasm};
use opcore::{Client, Item, ItemParams, Listed};
use std::cell::{RefCell, RefMut};

#[derive(Debug)]
pub enum OpError {
    /// The item does not exist.
    NoItem,
    Failed(String),
}

impl From<opcore::Error> for OpError {
    fn from(e: opcore::Error) -> OpError {
        match e {
            opcore::Error::NoItem(_) => OpError::NoItem,
            e => OpError::Failed(e.to_string()),
        }
    }
}

/// The item requests the vault store makes, each one request to 1Password,
/// none of which spends a read of the Budget but a write's own.
pub trait Op {
    /// The active items tagged `tag`.
    fn list(&self, tag: &str) -> Result<Vec<Listed>, OpError>;
    /// The items `ids`, in order, each none if the vault has no active one.
    fn get_all(&self, ids: &[&str]) -> Result<Vec<Option<Item>>, OpError>;
    /// Creates an item from `params`; the item 1Password answered.
    fn create(&self, params: &ItemParams) -> Result<Item, OpError>;
    /// Replaces item `id`'s title, category, fields, sections, notes and
    /// tags with `params`'; the item 1Password answered.
    fn edit(&self, id: &str, params: &ItemParams) -> Result<Item, OpError>;
    /// Archives item `id` (it can be restored in 1Password).
    fn archive(&self, id: &str) -> Result<(), OpError>;
}

type SignIn<C> = Box<dyn Fn() -> Result<Client<C>, opcore::Error>>;

/// opcore's Client on one vault, signed in on the first request (a sign-in
/// is seconds): a command that answers from the copy never signs in.
pub struct Opcore<C: Core = Wasm> {
    sign_in: SignIn<C>,
    client: RefCell<Option<Client<C>>>,
}

impl Opcore<Wasm> {
    /// The real Core, as service account `token` on vault `vault`.
    pub fn new(token: &str, vault: &str) -> Opcore<Wasm> {
        let (t, v) = (token.to_string(), vault.to_string());
        Opcore::with(Box::new(move || Client::sign_in(&t, &v)))
    }
}

impl<C: Core> Opcore<C> {
    pub fn with(sign_in: SignIn<C>) -> Opcore<C> {
        Opcore {
            sign_in,
            client: RefCell::new(None),
        }
    }

    /// The Client, signed in first if this is the first request.
    fn client(&self) -> Result<RefMut<'_, Client<C>>, OpError> {
        let mut slot = self.client.borrow_mut();
        if slot.is_none() {
            let signed_in =
                (self.sign_in)().map_err(|e| OpError::Failed(format!("signing in: {e}")))?;
            *slot = Some(signed_in);
        }
        Ok(RefMut::map(slot, |c| {
            c.as_mut().unwrap_or_else(|| unreachable!("signed in above"))
        }))
    }
}

impl<C: Core> Op for Opcore<C> {
    fn list(&self, tag: &str) -> Result<Vec<Listed>, OpError> {
        Ok(self.client()?.list(tag)?)
    }

    /// One `get_all`; an id the vault lacks fails it whole, so it is asked
    /// again without that id (only when an item went since it was listed).
    fn get_all(&self, ids: &[&str]) -> Result<Vec<Option<Item>>, OpError> {
        let mut got: Vec<Option<Item>> = vec![None; ids.len()];
        let mut left: Vec<usize> = (0..ids.len()).collect();
        while !left.is_empty() {
            let asked: Vec<&str> = left.iter().map(|&i| ids[i]).collect();
            match self.client()?.get_all(&asked) {
                Ok(items) => {
                    for (&i, item) in left.iter().zip(items) {
                        got[i] = Some(item);
                    }
                    break;
                }
                Err(opcore::Error::NoItem(gone)) => {
                    let before = left.len();
                    left.retain(|&i| ids[i] != gone);
                    if left.len() == before {
                        return Err(OpError::Failed(format!("no item `{gone}`, not asked for")));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(got)
    }

    fn create(&self, params: &ItemParams) -> Result<Item, OpError> {
        let mut made = self.client()?.create_all(std::slice::from_ref(params))?;
        made.pop()
            .ok_or_else(|| OpError::Failed("1Password answered no item".into()))
    }

    fn edit(&self, id: &str, params: &ItemParams) -> Result<Item, OpError> {
        Ok(self.client()?.edit(id, params)?)
    }

    fn archive(&self, id: &str) -> Result<(), OpError> {
        Ok(self.client()?.archive_all(&[id])?)
    }
}

/// A vault in memory, answering as opcore does where sesame depends on it,
/// and recording each request as one line: `list <tag>`, `get_all <id>…`,
/// `create <title>`, `edit <id>`, `archive <id>`.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct Memory(std::rc::Rc<RefCell<MemoryState>>);

#[cfg(test)]
#[derive(Default)]
pub struct MemoryState {
    pub items: Vec<Item>,
    pub calls: Vec<String>,
    /// Ids a listing leaves out, as 1Password may a new item.
    pub unlisted: Vec<String>,
    next_id: u64,
    clock: u64,
}

#[cfg(test)]
impl MemoryState {
    /// A new `updatedAt`, as each write gets.
    fn tick(&mut self) -> String {
        self.clock += 1;
        format!("t{}", self.clock)
    }
}

#[cfg(test)]
impl Memory {
    pub fn state(&self) -> std::cell::RefMut<'_, MemoryState> {
        self.0.borrow_mut()
    }

    /// The requests made since the last `take_calls`.
    pub fn take_calls(&self) -> Vec<String> {
        std::mem::take(&mut self.state().calls)
    }

    /// The item titled `title`, as 1Password holds it.
    pub fn item(&self, title: &str) -> Option<Item> {
        self.state().items.iter().find(|i| i.title == title).cloned()
    }

    /// Changes item `title` as another machine would: a new version.
    pub fn change(&self, title: &str, f: impl FnOnce(&mut Item)) {
        let mut s = self.state();
        let at = s.tick();
        let item = s.items.iter_mut().find(|i| i.title == title).unwrap();
        f(item);
        item.version += 1;
        item.updated_at = at;
    }

    /// Creates an item as another machine would; its id.
    pub fn add(&self, params: ItemParams) -> String {
        let item = self.create(&params).ok().unwrap();
        self.state().calls.pop();
        item.id
    }
}

#[cfg(test)]
impl Op for Memory {
    fn list(&self, tag: &str) -> Result<Vec<Listed>, OpError> {
        let mut s = self.state();
        s.calls.push(format!("list {tag}"));
        Ok(s.items
            .iter()
            .filter(|i| i.tags.iter().any(|t| t == tag))
            .filter(|i| !s.unlisted.contains(&i.id))
            .map(|i| Listed {
                id: i.id.clone(),
                title: i.title.clone(),
                tags: i.tags.clone(),
                updated_at: i.updated_at.clone(),
            })
            .collect())
    }

    fn get_all(&self, ids: &[&str]) -> Result<Vec<Option<Item>>, OpError> {
        let mut s = self.state();
        s.calls.push(format!("get_all {}", ids.join(" ")));
        Ok(ids
            .iter()
            .map(|id| s.items.iter().find(|i| i.id == *id).cloned())
            .collect())
    }

    fn create(&self, params: &ItemParams) -> Result<Item, OpError> {
        let mut s = self.state();
        s.calls.push(format!("create {}", params.title));
        s.next_id += 1;
        let item = Item {
            id: format!("id{}", s.next_id),
            version: 1,
            updated_at: s.tick(),
            ..from_params(params)
        };
        s.items.push(item.clone());
        Ok(item)
    }

    fn edit(&self, id: &str, params: &ItemParams) -> Result<Item, OpError> {
        let mut s = self.state();
        s.calls.push(format!("edit {id}"));
        let at = s.tick();
        let item = s
            .items
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or(OpError::NoItem)?;
        *item = Item {
            id: item.id.clone(),
            version: item.version + 1,
            updated_at: at,
            kept: item.kept.clone(),
            ..from_params(params)
        };
        Ok(item.clone())
    }

    fn archive(&self, id: &str) -> Result<(), OpError> {
        let mut s = self.state();
        s.calls.push(format!("archive {id}"));
        let at = s.items.iter().position(|i| i.id == id).ok_or(OpError::NoItem)?;
        s.items.remove(at);
        Ok(())
    }
}

#[cfg(test)]
fn from_params(p: &ItemParams) -> Item {
    Item {
        title: p.title.clone(),
        category: p.category,
        tags: p.tags.clone(),
        notes: p.notes.clone(),
        fields: p.fields.clone(),
        sections: p.sections.clone(),
        ..Default::default()
    }
}
