import tkinter as tk
from tkinter import messagebox

# 定义 S 盒和逆 S 盒，用于字节替代和逆替代操作
S_BOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_S_BOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]


# 密钥扩展，将 10 位密钥生成 6 个子密钥字
def key_expansion(key):
    w = [0] * 6
    w[0] = (key & 0xFF00) >> 8
    w[1] = key & 0x00FF
    w[2] = w[0] ^ 0x80 ^ sub_nibble(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ 0x30 ^ sub_nibble(w[3])
    w[5] = w[4] ^ w[3]
    return w


# nibble 替代，用于密钥扩展
def sub_nibble(nibble):
    return (S_BOX[nibble & 0x0F] << 4) | S_BOX[(nibble & 0xF0) >> 4]


# 字节替代，用 S 盒替换每个字节
def sub_bytes(state):
    return (
            (S_BOX[(state & 0xF000) >> 12] << 12) |
            (S_BOX[(state & 0x0F00) >> 8] << 8) |
            (S_BOX[(state & 0x00F0) >> 4] << 4) |
            (S_BOX[state & 0x000F])
    )


# 逆字节替代，使用逆 S 盒还原每个字节
def inv_sub_bytes(state):
    return (
            (INV_S_BOX[(state & 0xF000) >> 12] << 12) |
            (INV_S_BOX[(state & 0x0F00) >> 8] << 8) |
            (INV_S_BOX[(state & 0x00F0) >> 4] << 4) |
            (INV_S_BOX[state & 0x000F])
    )


# 轮密钥加，状态和轮密钥按位异或
def add_round_key(state, key):
    return state ^ key


# 行移位，交换低 4 位和次高 4 位
def shift_rows(state):
    row0 = state & 0xF0F0
    row1 = ((state & 0x0F00) >> 8) | ((state & 0x000F) << 8)
    return row0 | row1


# 列混合，对每个字节使用 GF(2^4) 乘法
def mix_columns(state):
    t0 = (state & 0xF000) >> 12
    t2 = (state & 0x0F00) >> 8
    t1 = (state & 0x00F0) >> 4
    t3 = state & 0x000F
    return ((t0 ^ mul4(t2)) << 12) | ((t2 ^ mul4(t0)) << 8) | ((t1 ^ mul4(t3)) << 4) | (t3 ^ mul4(t1))


# 逆列混合操作
def inv_mix_columns(state):
    t0 = (state & 0xF000) >> 12
    t2 = (state & 0x0F00) >> 8
    t1 = (state & 0x00F0) >> 4
    t3 = state & 0x000F
    return ((mul9(t0) ^ mul2(t2)) << 12) | ((mul2(t0) ^ mul9(t2)) << 8) | ((mul9(t1) ^ mul2(t3)) << 4) | (
                mul2(t1) ^ mul9(t3))


# GF(2^4) 下的乘法
def mul2(nibble):
    return ((nibble << 1) & 0xF) ^ 0x3 if (nibble & 0x8) else (nibble << 1) & 0xF


def mul4(nibble):
    return mul2(mul2(nibble)) & 0xF


def mul9(nibble):
    return (mul4(mul2(nibble)) ^ nibble) & 0xF


# S-AES 加密
def s_aes_encrypt(plaintext, key):
    w = key_expansion(key)
    state = add_round_key(plaintext, (w[0] << 8) | w[1])  # 初始轮密钥加
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, (w[2] << 8) | w[3])  # 第二轮密钥加
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, (w[4] << 8) | w[5])  # 第三轮密钥加
    return state


# S-AES 解密
def s_aes_decrypt(ciphertext, key):
    w = key_expansion(key)
    state = add_round_key(ciphertext, (w[4] << 8) | w[5])  # 第三轮密钥加
    state = shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, (w[2] << 8) | w[3])  # 第二轮密钥加
    state = inv_mix_columns(state)
    state = shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, (w[0] << 8) | w[1])  # 初始轮密钥加
    return state


# 双重加密的加密函数
def encrypt():
    try:
        plaintext = int(entry_plaintext.get(), 2)
        key = int(entry_key.get(), 2)
        if plaintext < 0 or plaintext > 0xFFFF or key < 0 or key > 0xFFFFFFFF:
            raise ValueError("明文必须是16位二进制数，密钥必须是32位二进制数。")

        key1, key2 = (key & 0xFFFF0000) >> 16, key & 0x0000FFFF
        ciphertext = s_aes_encrypt(s_aes_encrypt(plaintext, key1), key2)  # 双重加密
        entry_ciphertext.delete(0, tk.END)
        entry_ciphertext.insert(tk.END, format(ciphertext, '016b'))
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))


# 双重加密的解密函数
def decrypt():
    try:
        ciphertext = int(entry_ciphertext.get(), 2)
        key = int(entry_key.get(), 2)
        if ciphertext < 0 or ciphertext > 0xFFFF or key < 0 or key > 0xFFFFFFFF:
            raise ValueError("密文必须是16位二进制数，密钥必须是32位二进制数。")

        key1, key2 = (key & 0xFFFF0000) >> 16, key & 0x0000FFFF
        plaintext = s_aes_decrypt(s_aes_decrypt(ciphertext, key2), key1)  # 双重解密
        entry_plaintext.delete(0, tk.END)
        entry_plaintext.insert(tk.END, format(plaintext, '016b'))
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))


# 创建主窗口
root = tk.Tk()
root.title("S-AES加密解密")
root.geometry("400x250")
root.config(bg="#F5F5F5")

label_font, entry_font = ("Arial", 12), ("Arial", 10)

# 明文、密钥输入
tk.Label(root, text="输入明文(16bit):", font=label_font, bg="#F5F5F5").pack(pady=5)
entry_plaintext = tk.Entry(root, width=20, font=entry_font)
entry_plaintext.pack(pady=5)

tk.Label(root, text="输入密钥(32bit):", font=label_font, bg="#F5F5F5").pack(pady=5)
entry_key = tk.Entry(root, width=20, font=entry_font)
entry_key.pack(pady=5)

# 密文输出
tk.Label(root, text="输出密文(16bit):", font=label_font, bg="#F5F5F5").pack(pady=5)
entry_ciphertext = tk.Entry(root, width=20, font=entry_font)
entry_ciphertext.pack(pady=5)

# 加密与解密按钮
frame_buttons = tk.Frame(root, bg="#F5F5F5")
frame_buttons.pack(pady=10)
tk.Button(frame_buttons, text="加密", font=label_font, command=encrypt).grid(row=0, column=0, padx=5)
tk.Button(frame_buttons, text="解密", font=label_font, command=decrypt).grid(row=0, column=1, padx=5)

# 运行主循环
root.mainloop()
