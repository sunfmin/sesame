# The contract's vault: SESAME_CONTRACT_VAULT, else sesame-scratch (the
# vault of mytokens profile sesame-scratch, whose service account sees it
# alone). Sourced by fake-op, real-op-ready and scenario.sh.
vault=${SESAME_CONTRACT_VAULT:-sesame-scratch}
