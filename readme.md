
# OpCode 3-Gram Deep Learning POC

## Introduction
Often, people use Portable Executable (PE) models and engineered features (e.g., specific APIs) for malware detection and classification. PE Feature model provides robust performance in identifying malicious executables. However, to further improve the efficacy and robustness of these models, incorporating opcode n-grams can be a valuable approach. Opcode n-grams are sequences of machine-level instructions that can provide valuable insights into the behavior and structure of a program. This one-pager outlines why opcode n-grams are an additional feature for the existing PE feature model.

1.	Improved Detection Accuracy: Opcode n-grams have been demonstrated to improve detection accuracy in malware classification. By capturing the sequential relationships between instructions, opcode n-grams better represent the program's behavior (Santos et al., 2013)[1](#references). This additional information can enable the PE feature model to identify malicious patterns more accurately, increasing the detection rate and reducing false positives.
2.	Robustness against Evasion Techniques: Malware authors employ various evasion techniques, such as packing, encryption, and polymorphism, to avoid detection (Alazab et al., 2012)[2](#references). Opcode n-grams can increase the robustness of PE models against these techniques by capturing the underlying behavior of the malware, even when its appearance has been obfuscated. This enables the model to identify  malicious patterns despite the evasion techniques employed.
3.	Platform Independence: Opcode n-grams can provide platform-independent features for malware analysis, allowing for the detection of cross-platform malware (Canzanese et al., 2015)[3](#references). This is particularly important as attackers increasingly target multiple platforms simultaneously. By incorporating opcode n-grams into our ensemble, the model can be extended to support the analysis of malware on different platforms, increasing its versatility.


# Opcodes 3-Gram POC
The POC consists of two scripts. The ```opcode_3-gram.py``` script is a Keras-based model generator.  The second script, ```get_asm_exec.py``` disassembles the executable sections of the binary file. 

## Disassembling
The ```get_asm_exec.py``` script disassembles the executable sections of the binary file, not the entire file (chosen for code complexity and size of output).   Specifically, in the case of ELF files, it disassembles the executable segments, and for PE files, it disassembles the executable sections. 

* For ELF files, the script iterates over the segments and checks if the segment has the executable flag set (segment['p_flags'] & 0x1). If the flag is set, it disassembles that segment.
* For PE files, the script iterates over the sections and checks if the section has the IMAGE_SCN_MEM_EXECUTE flag set. If the flag is set, it disassembles that section.

I chose to use the [Capstone Engine](https://www.capstone-engine.org/) for disassembling because  Capstone is designed to work across various platforms (Windows, macOS, Linux, etc.) and supports multiple architectures, such as x86, x86_64, ARM, MIPS, and more with supporting multiple language bindings.


## Disassembling Choices
Regarding disassembling only the executable segments versus the whole binary, there are pros and cons to each approach. Disassembling only the executable segments can help focus on the actual code that gets executed, which is likely to be more relevant for malware analysis. This can also speed up the disassembly process and reduce the amount of noise in the data.

On the other hand, disassembling the whole binary can help capture additional information, such as data embedded in the code or code hidden in non-executable sections. In some cases, this additional information may be useful for malware analysis.

Pros:
* Focusing on executable segments: By disassembling only the executable sections of the binary, the script is 
    concentrating on the code that is most relevant for malware detection. This can help improve the efficiency 
    and accuracy of the ML model by eliminating noise from non-executable sections.

* Architecture-aware disassembly: The script uses the Capstone disassembly library, which is capable of handling multiple architectures, including x86, x86_64, ARM, MIPS, and others. This flexibility allows the script to handle a wider range of malware samples.

* N-gram representation: N-grams are a simple yet powerful representation for capturing local patterns in the instruction sequences. This can help the ML model to learn and identify the common behavior patterns across different malware families.

Cons:
* Loss of global structure: By focusing on n-grams, the approach may lose some information about the global structure of the binary. This might result in reduced detection capabilities for certain types of malware that exhibit unique global structures.

* Exclusion of non-executable data: Some malware might include valuable information in non-executable sections, such as strings, configuration data, or encrypted payloads. By disassembling only the executable segments, the script might miss out on such valuable information that could be useful for malware detection.

Despite the cons, disassembling only the executable segments can be beneficial for many malware analysis tasks. Research in this area has shown that features derived from disassembled code are often more informative than features derived from the raw binary. For example, the paper "Malware Detection by Eating a Whole EXE" by Bilar (2007)[4](#references) demonstrated that disassembly-based features can be effective for detecting malware.

In summary, while the given Python script is not perfect, it does represent a reasonable approach for preprocessing binaries into n-grams for use in ML models. The decision to focus on executable segments is supported by the fact that this is where the most relevant information for malware analysis is typically found.

## Objdump Approximate Equivalent Command

```
objdump -d -M intel <input_file> > <output_file>
```

```-d``` option tells objdump to disassemble the binary file.

```-M``` intel option sets the disassembly output syntax to the Intel-style assembly language. 

The objdump command will disassemble the binary files based on the detected architecture and write the output to the specified output file. For unsupported file formats, you may need to specify the architecture manually using the -m option followed by the architecture name (e.g., -m i386 for x86 or -m i386:x86-64 for x86_64). Note that the command may not produce the exact same output as the provided Python script for the following reasons:

* The Python script uses the Capstone disassembly framework, whereas objdump uses the disassembler from the GNU Binutils package. These disassemblers might have slightly different interpretations of certain instructions or might represent them in a slightly different format.

* The Python script specifically disassembles **ONLY** the executable segments for ELF files or executable sections for PE files. objdump, on the other hand, disassembles all sections containing code by default.

* The Python script outputs only the instruction mnemonics, whereas objdump provides more information, such as the instruction address, opcode bytes, and operands.

## Pre-process Files Example
```
for file in *; do python3 ../get_assm_exec.py "$file" 3 ../asm_files/"$file".asm ../malicious_3grams/"$file".txt; done
```

## OpCode 3-Gram Keras Model Considerations -  Input File & the Vectorizer 
Whether the input file contains one opcode per line or multiple opcodes per line matters when you preprocess the data for your 
machine learning model. The way you preprocess the data should be consistent with the structure of the input file.

One opcode per line, the input file will look like this:
```
jmp
add
mov
...
```

Multiple opcodes per line, i.e. 3-Grams the input file will look like this:
```
jmp add mov
add mov xor
mov xor jmp
...
```
When using TfidfVectorizer, you should tokenize the input file correctly based on its structure. By default, TfidfVectorizer tokenizes input text using a regular expression that matches words (alphanumeric sequences). This default setting works well when you have one opcode per line. However, if you have multiple opcodes per line, you need to customize the tokenization process to split lines by whitespace.

You can customize the tokenization process by providing a custom tokenizer function or regular expression to the TfidfVectorizer:

Example:
```
# Define a custom tokenizer function that splits the input text by whitespace.
def custom_tokenizer(text):
    return text.split()

# Use the custom tokenizer with TfidfVectorizer.
vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), tokenizer=custom_tokenizer)
```

Alternatively, you can use a regular expression to match whitespace-separated opcodes:

```
vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), token_pattern=r'\b\w+\b')
```

In summary, it does matter whether the input file contains one opcode per line or multiple opcodes per line. Ensure that the preprocessing is consistent with the input file structure by using an appropriate tokenizer or token pattern with TfidfVectorizer.

Further the effectiveness of using opcodes and n-grams depends on various factors, such as the choice of n, the quality of disassembly, and the specific malware samples being analyzed. In some cases, using just the opcodes without the operands may be sufficient to achieve good results. In other cases, including operands may provide additional context and improve the model's performance.

## Prior Art
* [N-gram-based detection of new malicious code](https://ieeexplore.ieee.org/document/1342667)
* [Learning to Detect and Classify Malicious Executables in the Wild](https://www.jmlr.org/papers/volume7/kolter06a/kolter06a.pdf)
* [Unknown malcode detection and the imbalance problem](https://link.springer.com/article/10.1007/s11416-009-0122-8)
* [Malware Detection and Classification Based on N-Grams Attribute Similarity](https://ieeexplore.ieee.org/document/8005908)
* [Detecting unknown malicious code by applying classification techniques on OpCode patterns](https://security-informatics.springeropen.com/articles/10.1186/2190-8532-1-1)
* [N-gram Opcode Analysis for Android Malware Detection](https://pureadmin.qub.ac.uk/ws/portalfiles/portal/127240417/N_gram.pdf)
* [Malware detection through opcode sequence
analysis using machine learning](https://ntnuopen.ntnu.no/ntnu-xmlui/bitstream/handle/11250/2515371/SimenBragen.pdf?sequence=1)

## References
1. Santos, I., Nieves, J., & Bringas, P. G. (2013). Opcode sequences as representation of executables for data-mining-based unknown malware detection. Information Sciences, 227, 28-37. 
2. Alazab, M., Venkatraman, S., Watters, P., & Alazab, M. (2012). Zero-day malware detection based on supervised learning algorithms of API call signatures. In Proceedings of the Ninth Australasian Data Mining Conference (Vol. 134, pp. 171-182).
3. Canzanese, R., Kam, M., & Mancoridis, S. (2015). Toward an automatic, online behavioral malware classification system. In 2015 10th International Conference on Availability, Reliability and Security (pp. 508-516). IEEE.
4. Bilar, D. (2007). Malware Detection by Eating a Whole EXE. Proceedings of the 4th Workshop on Bioinformatics and Machine Learning, Tufts University, Medford, MA, USA.

## Testing Data
Testing data was pulled from [Malware Data Science](https://www.malwaredatascience.com/code-and-data), specifically ch8/data

```
              precision    recall  f1-score   support

           0       0.97      0.96      0.97       192
           1       0.91      0.94      0.93        87

    accuracy                           0.95       279
   macro avg       0.94      0.95      0.95       279
weighted avg       0.95      0.95      0.95       279

Test loss: 0.1233430951833725
Test accuracy: 0.9534050226211548
python3 ./opcode_3-gram.py  49.21s user 4.52s system 98% cpu 54.449 total
```