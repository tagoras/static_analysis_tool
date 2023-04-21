import re


def extract_balanced_braces(text):
    stack = []
    code_blocks = []
    start = -1

    for i, char in enumerate(text):
        if char == '{':
            if not stack:  # If the stack is empty, this is a new code block
                start = i
            stack.append(char)
        elif char == '}':
            if stack and stack[-1] == '{':  # If the last opening brace matches
                stack.pop()
                if not stack:  # If the stack is empty, the code block has ended
                    code_blocks.append(text[start:i + 1])
            else:
                stack = []  # Reset the stack if there is an unmatched closing brace

    return code_blocks


def extract_functions(text):
    return re.findall(r"""(?P<function_name>\w+)\([^)]*\)""", text)


def replace_index_variables():
    with open("index_variables.txt", "r") as source_file:
        text = source_file.read()

        pattern = re.compile(r"""(?P<left_untouched>\b(?P<datatypes>char|int|bool|short|long|float|double|signed|unsigned)\s+(?P<buffer_name>\w+)\[(?P<buffer_index>\d+)]\s*;
                             .*for\s*\(.*\)\s*{[^{]*(?P=buffer_name)\[)(?P<weak_index>\w+)(?P<right_untouched>][^{]*})"""
                             , re.VERBOSE | re.DOTALL)

        res = pattern.sub(r"\g<left_untouched>\g<weak_index>%\g<buffer_index>\g<right_untouched>", text)
        # print(res)

        source_file.close()


def replace_signed_index_variables():
    def match_change(string_match: re.Match):
        possible_vulnerability = string_match.group("vulnerability")
        print(possible_vulnerability)
        possible_vulnerability = possible_vulnerability.strip()
        rest_of_string = string_match.group("untouched")
        match possible_vulnerability:
            case "signed short" | "short":
                return "unsigned short" + rest_of_string
            case "signed int" | "int":
                return "unsigned int" + rest_of_string
            case "signed char | char":
                return "unsigned char" + rest_of_string
            case "bool":
                return "bool" + rest_of_string
            case "signed":
                return "unsigned" + rest_of_string
            case "long" | "signed long":
                return "unsigned long" + rest_of_string
            case "float" | "signed float":
                return "unsigned float" + rest_of_string
            case "double" | "signed double":
                return "unsigned double" + rest_of_string
            case "char" | "signed char":
                return "unsigned char" + rest_of_string
            case _:
                return possible_vulnerability + rest_of_string

    with open("overflows_underflows.txt", "r") as source_file:
        text = source_file.read()

        # Find usage of signed index variables in while loops
        pattern = re.compile(r"""(?P<vulnerability>\b(?P<datatypes>unsigned|char|int|bool|signed|short|long|float|double|struct)(\s+(char|int|bool|signed|short|long|float|double|struct))*)
        (?P<untouched>\s*(?P<var>\w+)[^}]*(?P<while>\s*\s*{[^{]*\[(?P=var)][^{]*}))""",
                             re.VERBOSE | re.DOTALL)

        result = pattern.sub(match_change, text)
        print(result)
        source_file.close()


def add_null_character():
    with open("null_termination.txt", "r") as source_file:
        text = source_file.read()
        res = extract_balanced_braces(text)

        for code_block in res:
            # First we need to check if the code block contains a dangerous pattern of initialising a char buffer
            # In a dangerous way and then if it tries to attempt to print it at some point in the code block
            buffer_print_regex = re.compile(r"""(?P<left>\{.*(?P<buffer_declaration>char\s+(?P<buffer_name>\w+)\[(?P<buffer_size>\d+)]\s*;).*?)
            (?P<insert_place>\s)(?P<right>(?P<printing_buffer>\w*pr\w*\(\s*\".*?\"[^)]*?(?P=buffer_name).*\)\s*;).*})""",
                                            re.VERBOSE | re.DOTALL)
            match = buffer_print_regex.search(code_block)
            if match:
                null_termination_regex = re.compile(r"""\w+\s*\[\d+]\s*=\s*'\\0'\s*;""", re.VERBOSE | re.DOTALL)
                null_termination = null_termination_regex.search(match.group())
                if not null_termination:
                    correct_index = int(match.group("buffer_size")) - 1
                    correct_string = match.group("left") + match.group("buffer_name") + "[" + str(
                        correct_index) + "] = '\\0';\n" + match.group("right")
                    print(correct_string)

        source_file.close()

def unsafe_function(functions: list):
    unsafe_functions = ["strcpy", "strcat", "sprintf", "gets", "sscanf", "fscanf", "scanf", "fread", "read", "memmove"]
    unsafe_function_list = []
    for function in functions:
        if function in unsafe_functions:
            unsafe_function_list.append(function)
    return unsafe_function_list


def replace_unsafe_function(code_block, function_list):
    replacements = {"strcpy":"strncpy", "strcat":"strncat", "sprintf": "snprintf", "gets":"gets_s", "scanf":"sscanf"}
    new_code_block = ""
    for function in function_list:
        replacement = replacements[function]
        match replacement:
            case "strncpy" | "strncat":
                print(code_block)
                pattern = re.compile(function + r"""\(\s*(?P<arg1>\w+)\s*,\s*(?P<arg2>\w+)\s*\)""", re.DOTALL | re.VERBOSE)
                new_code_block = pattern.sub(replacement+"(\g<arg1>,\g<arg2>,sizeof(\g<arg1>))", code_block, re.VERBOSE | re.DOTALL)
                print(new_code_block)
            case "snprintf":
                pattern = re.compile(function + r"""\(\s*(?P<arg1>\w+)\s*,(?P<right_side>.*?\))""", re.DOTALL | re.VERBOSE)
                new_code_block = pattern.sub(replacement+"(\g<arg1>, sizeof(\g<arg1>),\g<right_side>)", code_block, re.VERBOSE | re.DOTALL)
                print(new_code_block)
            case "gets_s":
                pattern = re.compile(function + r"""(?P<function_name>\w+)\(\s*(?P<arg1>\w+)\s*\)""", re.DOTALL | re.VERBOSE)
                new_code_block = pattern.sub(replacement+"(\g<arg1>, sizeof(\g<arg1>))", code_block, re.VERBOSE | re.DOTALL)
                print(new_code_block)
            case "sscanf":
                pattern = re.compile(function + r"""\(\"[^\"]*\"\s*,\s*(?P<buffer_name>\w+)\s*\)""", re.VERBOSE | re.DOTALL)
                new_code_block = pattern.sub(replacement+ "")

    return new_code_block


def replace_unsafe_functions():
    with open("unsafe_functions.txt", "r") as source_file:
        text = source_file.read()
        code_blocks = extract_balanced_braces(text)
        for code_block in code_blocks:
            function_list = extract_functions(code_block)
            #print(code_block)
            replace_unsafe_function(code_block, function_list)
            #print(function_list)
            print("#####################################")


if __name__ == "__main__":
    # replace_index_variables()
    # replace_signed_index_variables()
    # add_null_character()
    replace_unsafe_functions()
