#!/usr/bin/env python3
__author__ = 'Matthew Schwartz'

import sys
from itertools import islice

#from capstone import *
import capstone
import magic
import pefile
from elftools.elf.elffile import ELFFile

#from collections import Counter

def disassemble_elf(input_file):
    with open(input_file, 'rb') as f:
        elf_file = ELFFile(f)
        code = bytearray()
        base_addr = None

        for segment in elf_file.iter_segments():
            if segment['p_flags'] & 0x1:  # Check if the segment is executable
                code += bytes(segment.data())
                if base_addr is None or segment['p_vaddr'] < base_addr:
                    base_addr = segment['p_vaddr']

        # Configure Capstone based on the ELF file's architecture
        arch = elf_file.get_machine_arch()
        if arch == 'x86':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif arch == 'x64':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            raise Exception(f"Unsupported architecture: {arch}")

        disassembly = md.disasm(bytes(code), base_addr)
        instructions = [insn.mnemonic for insn in disassembly]

    return instructions

def disassemble_pe(input_file):
    pe = pefile.PE(input_file)

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise Exception("Unsupported architecture")

    instructions = []

    for section in pe.sections:
        if section.IMAGE_SCN_MEM_EXECUTE:
            base_addr = section.VirtualAddress
            code = section.get_data()
            disassembly = md.disasm(bytes(code), base_addr)

            for insn in disassembly:
                instructions.append(insn.mnemonic)

    return instructions


def disassemble_binary(input_file):
    asm_file = input_file + '.asm'
    
    # Determine file type using python-magic
    file_type = magic.from_file(input_file)
    
    # Disassemble binary file
    with open(input_file, 'rb') as f:
        code = f.read()
        
    if 'ELF' in file_type:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif 'PE32' in file_type:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif 'PE32+' in file_type:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise Exception(f'Unsupported file format: {file_type}')
    
    with open(asm_file, 'w') as f:
        for i in md.disasm(code, 0x1000):
            f.write(f'0x{i.address:x}\t{i.mnemonic}\t{i.op_str}\n')
    
    return file_type, asm_file

def generate_ngrams(instructions, n):
    return zip(*[islice(instructions, i, None) for i in range(n)])


def save_ngrams_to_file(ngrams, output_file):
    with open(output_file, 'w') as f:
        for ngram in ngrams:
            f.write(" ".join(ngram) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python combined_script.py <binary_file> <n_grams> <output_asm> <output_ngrams>")
        sys.exit(1)

    binary_file = sys.argv[1]
    n_grams = int(sys.argv[2])
    output_asm = sys.argv[3]
    output_ngrams = sys.argv[4]

    magic_detector = magic.Magic()
    file_type = magic_detector.from_file(binary_file)

    try:
        if "ELF" in file_type:
            instructions = disassemble_elf(binary_file)
        elif "PE32" in file_type:
            instructions = disassemble_pe(binary_file)
        else:
            raise Exception(f"Unsupported file type: {file_type}")

        # Save disassembled instructions to the output_asm file
        with open(output_asm, 'w') as f:
            for instruction in instructions:
                f.write(instruction + "\n")

        ngrams = generate_ngrams(instructions, n_grams)
        save_ngrams_to_file(ngrams, output_ngrams)

        print(f"Assembly output written to: {output_asm}")
        print(f"N-gram output written to: {output_ngrams}")

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
