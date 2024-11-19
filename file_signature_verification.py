import hashlib
import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox


# 计算文件哈希值
def get_file_hash(file_path, hash_algorithm='sha256'):
    """计算文件的哈希值并返回"""
    hash_obj = hashlib.new(hash_algorithm)
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(4096):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except FileNotFoundError:
        print(f"文件 {file_path} 不存在，请检查路径。")
        return None


# 验证文件的签名
def verify_file_signature(file_path, known_signatures, hash_algorithm='sha256', lang='en'):
    """验证文件的哈希值是否在已知签名中"""
    file_hash = get_file_hash(file_path, hash_algorithm)
    if file_hash is None:
        return
    messages = {
        'en': {
            'success': f"The hash of the file {file_path} matches. The file is legitimate.",
            'warning': f"Warning: The file {file_path} may have been tampered with or is not legitimate!",
        },
        'cn': {
            'success': f"文件 {file_path} 的哈希值匹配，文件合法。",
            'warning': f"警告：文件 {file_path} 可能被篡改或不合法！",
        }
    }
    lang_msgs = messages.get(lang, messages['en'])

    # 获取当前时间
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    # 根据文件是否合法设置颜色
    if file_hash in known_signatures:
        result_text.insert(tk.END, f"[{current_time}] {lang_msgs['success']}\n", 'normal')  # 黑色（正常）
    else:
        result_text.insert(tk.END, f"[{current_time}] {lang_msgs['warning']}\n", 'virus')  # 红色（病毒）


# 启发式检测
def heuristic_detection(file_path):
    """启发式检测：检查文件扩展名和文件修改时间"""
    suspicious_extensions = [ '.dll', '.bat']
    suspicious_time_threshold = 24 * 60 * 60  # 24小时内的修改时间
    _, file_extension = os.path.splitext(file_path)

    # 扩展名检查
    if file_extension.lower() in suspicious_extensions:
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        result_text.insert(tk.END,
                           f"[{current_time}] Warning: File {file_path} has a suspicious extension ({file_extension}).\n",
                           'virus')

    # 修改时间检查
    try:
        file_mod_time = os.path.getmtime(file_path)
        current_time = time.time()
        time_diff = current_time - file_mod_time
        if time_diff < suspicious_time_threshold:
            current_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())  # 获取当前时间
            result_text.insert(tk.END,
                               f"[{current_time_str}] Warning: File {file_path} was modified in the last 24 hours.\n",
                               'virus')
    except FileNotFoundError:
        result_text.insert(tk.END, f"File {file_path} does not exist. Please check the path.\n", 'normal')


# 扫描文件夹
def scan_file_system(directory, known_signatures, hash_algorithm='sha256', lang='en'):
    """递归扫描文件夹中的文件，并验证它们的合法性"""
    result_text.insert(tk.END, f"Scanning directory: {directory}\n")  # 显示扫描的文件夹路径
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())  # 获取当前时间
    result_text.insert(tk.END, f"Scan started at {current_time}\n")  # 显示扫描开始时间

    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            result_text.insert(tk.END, f"Scanning file: {file_path}\n", 'normal')
            verify_file_signature(file_path, known_signatures, hash_algorithm, lang)
            heuristic_detection(file_path)


# 选择文件夹
def select_directory():
    """打开文件选择对话框，选择文件夹"""
    directory = filedialog.askdirectory()
    if directory:
        directory_entry.delete(0, tk.END)
        directory_entry.insert(0, directory)


# 启动扫描
def start_scan():
    """启动扫描，验证文件的签名"""
    directory = directory_entry.get()
    if not os.path.isdir(directory):
        messagebox.showerror("Error", "Please select a valid directory.")
        return

    # 在这里替换为您创建的合法文件哈希值
    known_signatures = {
        'legitimate_file_1_hash_here',  # 替换为合法文件 1 的哈希值
        'legitimate_file_2_hash_here',  # 替换为合法文件 2 的哈希值
        # 添加其他合法文件哈希值
    }

    lang = lang_var.get()
    result_text.delete(1.0, tk.END)  # 清空之前的结果
    scan_file_system(directory, known_signatures, hash_algorithm='sha256', lang=lang)


# 创建主窗口
root = tk.Tk()
root.title("File System Scanner")

# 创建UI元素
directory_label = tk.Label(root, text="Select Directory:")
directory_label.pack(pady=5)

directory_entry = tk.Entry(root, width=50)
directory_entry.pack(pady=5)

# 默认路径 E:\fanghuqifa
directory_entry.insert(0, "E:\\fanghuqifa")

browse_button = tk.Button(root, text="Browse", command=select_directory)
browse_button.pack(pady=5)

lang_var = tk.StringVar(value='en')
lang_label = tk.Label(root, text="Select Language:")
lang_label.pack(pady=5)

lang_frame = tk.Frame(root)
lang_frame.pack(pady=5)

lang_en = tk.Radiobutton(lang_frame, text="English", variable=lang_var, value='en')
lang_en.pack(side=tk.LEFT)

lang_cn = tk.Radiobutton(lang_frame, text="中文", variable=lang_var, value='cn')
lang_cn.pack(side=tk.LEFT)

scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack(pady=20)

result_text = tk.Text(root, height=20, width=80)
result_text.pack(pady=10)

# 配置字体标签
result_text.tag_configure('normal', foreground='black')  # 黑色字体
result_text.tag_configure('virus', foreground='red')  # 红色字体（病毒文件）

# 运行主循环
root.mainloop()
