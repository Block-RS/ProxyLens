def format_opcodes(input_file, output_file):
    with open(input_file, 'r') as f:
        content = f.read()

    # 提取 Opcodes 段
    lines = content.splitlines()
    opcodes_raw = ""
    for i, line in enumerate(lines):
        if line.strip().startswith("Opcodes:"):
            opcodes_raw = ' '.join(lines[i+1:]).strip()
            break
    if not opcodes_raw:
        print("No opcodes found.")
        return

    ops = opcodes_raw.split()
    offset = 0
    i = 0
    formatted = []

    while i < len(ops):
        op = ops[i]
        line = f"{offset:04X} {op}"

        if op.startswith("PUSH"):
            try:
                n = int(op[4:])
                operands = ops[i+1:i+2]  # solc 输出里参数只显示一个 word（不是逐字节显示）
                if operands:
                    line += f" {operands[0]}"
                    i += 1
                offset += 1 + n
            except:
                offset += 1
        else:
            offset += 1

        formatted.append(line)
        i += 1

    with open(output_file, "w") as f:
        f.write("\n".join(formatted))

    print(f"[✓] Formatted opcodes written to {output_file}")



# 用法
if __name__ == "__main__":
    format_opcodes("output.txt", "formatted_opcodes.txt")
