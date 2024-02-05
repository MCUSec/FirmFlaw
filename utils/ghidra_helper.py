from pathlib import Path
# helper funcs 
def get_language(id: str) -> "Language":
    from ghidra.program.util import DefaultLanguageService
    from ghidra.program.model.lang import LanguageID, LanguageNotFoundException
    try:
        service: "LanguageService" = DefaultLanguageService.getLanguageService()
        return service.getLanguage(LanguageID(id))
    except LanguageNotFoundException:
        # suppress the java exception
        pass
    raise ValueError("Invalid Language ID: "+id)
   
def get_compiler_spec(lang: "Language", id: str = None) -> "CompilerSpec":
    if id is None:
        return lang.getDefaultCompilerSpec()
    from ghidra.program.model.lang import CompilerSpecID, CompilerSpecNotFoundException
    try:
        return lang.getCompilerSpecByID(CompilerSpecID(id))
    except CompilerSpecNotFoundException:
        # suppress the java exception
        pass
    lang_id = lang.getLanguageID()
    raise ValueError(f"Invalid CompilerSpecID: {id} for Language: {lang_id.toString()}")

# for create handler functions 
def create_handlers(program: 'ghidra.program.model.listing.Program', flat_api: 'ghidra.program.flatapi') -> int:
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.symbol import RefType
    from ghidra.program.model.util   import CodeUnitInsertionException
    handler_name = ['MasterStackPointer', 'Reset_Handler', 'NMI_Handler', 'HardFault_Handler', 
     'MemManage_Handler', 'BusFault_Handler','UsageFault_Handler',
        'Reserved1_','Reserved2_','Reserved3_','Reserved4_',
     'SVC_Handler', 'Reserved5_','Reserved6_','PendSV_Handler','SysTick_Handler']
    i = 0
    program_len = int(program.getMaxAddress().subtract(program.getMinAddress()))
    image_base = int(program.getImageBase().getUnsignedOffset())
    while True:
        i += 1
        addr_ = flat_api.toAddr(image_base +4*i)
        handler_address = flat_api.getInt(addr_) - 1
        if handler_address == -1 or handler_address == 0xfffffffe:
            try:
                flat_api.createDWord(addr_)
            except CodeUnitInsertionException:
                pass 
            continue
        elif handler_address > image_base and (handler_address - image_base) < program_len:
            if i >= len(handler_name):
                name_ = 'IRQ' + str(i-16)+ '_Handler'
            else:
                name_ = handler_name[i]
            # create Data and reference 
            label_ = name_[:name_.find('_')]
            data_ = flat_api.createDWord(addr_)
            flat_api.createLabel(addr_, label_, True)
            flat_api.createMemoryReference(data_, flat_api.toAddr(handler_address), RefType.UNCONDITIONAL_CALL)
            # create Function 
            flat_api.disassemble(flat_api.toAddr(handler_address))
            newfunc = flat_api.createFunction(flat_api.toAddr(handler_address), name_)
            # rename thunk functions 
            if newfunc is None:
                  print(f"\033[31mCreate Function failed addr:{hex(handler_address)}, name:{name_}\033[0m")
            elif newfunc.getName()[:6] == 'thunk_':
                newfunc.setName(name_, SourceType.USER_DEFINED)
        else:
            return i 
            # not a correct handler 
            break

def openProject(project_name: str, project_location: Path) -> 'ghidra.base.project.GhidraProject': 
    from java.io import IOException
    from ghidra.base.project import GhidraProject
    # create or open project 
    try:
        project = GhidraProject.openProject(project_location, project_name, True)
        print(f'Opened project: {project.project.name}')
    except IOException:
        project = GhidraProject.createProject(project_location, project_name, False)
        print(f'Created project: {project.project.name}')
    return project