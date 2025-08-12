TEXT ·GetPEB(SB), $0-8
    MOVQ $0x1337, AX
    MOVQ $0xCAFECAFE, BX
    XORQ BX, AX
    MOVQ $0x28, CX 
    MOVQ $0x18, DX 
    ADDQ DX, CX   
    SUBQ $0x4, CX    
    SHLQ $1, CX      
    SHRQ $1, CX        
    ADDQ $0x24, CX     
    MOVQ $0xC0FFEE11, DX
    XORQ DX, AX
    PUSHQ AX
    POPQ AX
    MOVQ CX, BX             
    XORQ SI, SI            
    MOVQ $0xFEEDFACE, DI      
    BYTE $0x48             
    BYTE $0x31              
    BYTE $0xC0              
    BYTE $0x65            
    BYTE $0x48            
    BYTE $0x8B            
    BYTE $0x03            
    MOVQ $0xC4771E55, CX    
    XORQ CX, CX            
    PUSHQ BX               
    MOVQ AX, BX           
    POPQ DX               
    MOVQ BX, AX          
    INCQ CX
    DECQ CX
    MOVQ $0x9876, DX
    XORQ DX, DX
    PUSHQ AX
    PUSHQ CX
    PUSHQ DX
    POPQ DX
    POPQ CX
    POPQ AX
    MOVQ $0xC4771C47, BX
    XORQ BX, BX
    NOP
    NOP
    MOVQ AX, ret+0(FP)
    RET


TEXT ·WalkLDR(SB), $0-16
    MOVQ ldrPtr+0(FP), AX  
    TESTQ AX, AX           
    JZ null_ldr
    MOVQ $0x8, BX         
    MOVQ $0x8, CX           
    ADDQ CX, BX         
    MOVQ $0x1234, DX       
    XORQ DX, DX           
    ADDQ BX, AX           
    MOVQ (AX), AX       
    PUSHQ BX
    MOVQ $0xABCD, BX
    XORQ BX, BX
    POPQ BX
    JMP return_result

null_ldr:
    XORQ AX, AX        

return_result:
    MOVQ AX, ret+8(FP)
    RET

TEXT ·GetNextModule(SB), $0-16
    MOVQ currentModule+0(FP), AX  
    TESTQ AX, AX                
    JZ null_module
    MOVQ $0xFEED, BX
    MOVQ $0xFACE, CX  
    XORQ BX, CX
    PUSHQ CX
    POPQ CX
    MOVQ (AX), AX          
    MOVQ $0x9999, DX
    XORQ DX, DX
    INCQ BX
    DECQ BX
    JMP return_next
null_module:
    XORQ AX, AX           
return_next:
    MOVQ AX, ret+8(FP)
    RET

TEXT ·ReadModuleBase(SB), $0-16
    MOVQ modulePtr+0(FP), AX    
    TESTQ AX, AX               
    JZ null_base
    MOVQ $0x20, BX        
    MOVQ $0x10, CX        
    ADDQ CX, BX       
    MOVQ $0xC4771E5, DX
    XORQ DX, DX
    PUSHQ BX
    POPQ BX
    ADDQ BX, AX           
    MOVQ (AX), AX         
    JMP return_base
null_base:
    XORQ AX, AX      
return_base:
    MOVQ AX, ret+8(FP)
    RET
  

TEXT ·ReadModuleTimestamp(SB), $0-12
    MOVQ modulePtr+0(FP), AX   
    TESTQ AX, AX              
    JZ null_timestamp
    MOVQ $0x70, BX        
    MOVQ $0x10, CX     
    ADDQ CX, BX  
    MOVQ $0xC4771C, DX
    MOVQ $0xFEEDC47, SI
    XORQ DX, SI
    PUSHQ SI
    POPQ SI
    ADDQ BX, AX           
    MOVL (AX), AX          
    JMP return_timestamp

null_timestamp:
    XORL AX, AX          

return_timestamp:
    MOVL AX, ret+8(FP)      
    RET



TEXT ·ReadModuleName(SB), $0-20
    MOVQ modulePtr+0(FP), AX   
    TESTQ AX, AX             
    JZ null_name
    MOVQ $0x40, BX          
    MOVQ $0x8, CX           
    ADDQ CX, BX             
    MOVQ $0x1111, DX
    MOVQ $0x2222, SI
    XORQ DX, SI
    PUSHQ SI
    POPQ SI
    ADDQ BX, AX          
    MOVW (AX), BX         
    MOVQ 8(AX), CX        
    PUSHQ BX
    PUSHQ CX  
    POPQ CX
    POPQ BX
    JMP return_name
null_name:
    XORW BX, BX            
    XORQ CX, CX           

return_name:
    MOVW BX, ret+8(FP)   
    MOVQ CX, ret+16(FP)      
    RET
    
    