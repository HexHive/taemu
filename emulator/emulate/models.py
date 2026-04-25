

from dataclasses import dataclass
from enum import Enum
from typing import List


class TA_Function(Enum):
    CreateEntryPoint = "TA_CreateEntryPoint"
    OpenSessionEntryPoint = "TA_OpenSessionEntryPoint"
    InvokeCommandEntryPoint = "TA_InvokeCommandEntryPoint"
    CloseSessionEntryPoint = "TA_CloseSessionEntryPoint"
    DestroyEntryPoint = "TA_DestroyEntryPoint"
    
    CElfFile_invoke = "CElfFile_invoke"
    SetupTeardown = "setup_teardown"
    CommandHandler = "command_handler"

@dataclass
class StubbedFunction:
    name: TA_Function
    start: int
    end: List[int]
    base: int = 0
