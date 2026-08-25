from .params import *
import importlib.util, os
_spec = importlib.util.spec_from_file_location(
    "km3_base", os.path.join(os.path.dirname(__file__), "..", "km3", "harness.py"))
_m = importlib.util.module_from_spec(_spec); _m.__package__ = __package__
_spec.loader.exec_module(_m)
place_input_callback = _m.place_input_callback
