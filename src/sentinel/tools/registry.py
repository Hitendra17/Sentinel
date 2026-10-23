"""Fixed allowlist of read-only actions; arguments are validated before execution."""
REGISTRY={"recon.inspect":{"required":set(),"optional":set()}}

def validate_action(name, arguments):
    if name not in REGISTRY: raise ValueError("tool is not allowlisted")
    if not isinstance(arguments,dict): raise ValueError("tool arguments must be an object")
    spec=REGISTRY[name]
    if set(arguments)-spec["required"]-spec["optional"] or not spec["required"]<=set(arguments): raise ValueError("invalid tool arguments")
    return True
