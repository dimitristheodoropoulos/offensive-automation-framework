from core.adapters import global_registry
from adapters.proprietary_game_fuzzer import ProprietaryGameFuzzerAdapter

def initialize_osaf_tools():
    """Registers all available standard and proprietary tool adapters into the global registry."""
    global_registry.register(ProprietaryGameFuzzerAdapter())
    # Εδώ μπορούν να προστεθούν μελλοντικά adapters (π.χ. NmapAdapter, ZapAdapter κ.λπ.)