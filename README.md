# EasyTier-FFI 使用说明（C# 示例完整版）

> 本仓库基于  
> https://github.com/EasyTier/EasyTier  
> 进行 Fork 与扩展，实现：
>
> - 将 EasyTier 核心能力封装为标准 C ABI 动态库
> - 自动构建 Windows / Linux / macOS 跨平台动态库
> - 提供 C# / Python / Java 等多语言调用支持
>
> 本文档以 **C# 调用示例** 为主进行说明。

---

# 一、动态库说明

生成的动态库文件如下：

| 平台 | 文件名 |
|------|--------|
| Windows | easytier_ffi.dll |
| Linux | libeasytier_ffi.so |
| macOS | libeasytier_ffi.dylib |

调用约定：

- extern "C"
- CallingConvention.Cdecl
- UTF-8 字符串
- Rust 分配字符串需调用 free_string 释放

---

# 二、导出接口说明

## 1. parse_config

```c
int parse_config(const char* cfg_str);
```

功能：

- 解析 TOML 配置
- 仅校验语法
- 不启动实例

返回值：

- 0 成功
- -1 失败

---

## 2. run_network_instance

```c
int run_network_instance(const char* cfg_str);
```

功能：

- 解析配置
- 启动网络实例
- 注册实例名

返回值：

- 0 成功
- -1 失败

---

## 3. retain_network_instance

```c
int retain_network_instance(const char** inst_names, size_t length);
```

功能：

- 仅保留指定实例
- 传空数组则清空所有实例

---

## 4. collect_network_infos

```c
int collect_network_infos(KeyValuePair* infos, size_t max_length);
```

功能：

- 获取当前所有实例状态
- 返回填充数量
- value 为 JSON 字符串

---

## 5. get_error_msg

```c
void get_error_msg(const char** out);
```

获取最后一次错误信息。

---

## 6. free_string

```c
void free_string(const char* s);
```

释放 Rust 侧分配的字符串。

---

# 三、C# 完整封装类

```csharp
public class EasyTierFFI
{
    // 导入 DLL 函数
    private const string DllName = "easytier_ffi.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int parse_config([MarshalAs(UnmanagedType.LPStr)] string cfgStr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int run_network_instance([MarshalAs(UnmanagedType.LPStr)] string cfgStr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int retain_network_instance(IntPtr instNames, int length);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int collect_network_infos(IntPtr infos, int maxLength);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void get_error_msg(out IntPtr errorMsg);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void free_string(IntPtr str);

    // 定义 KeyValuePair 结构体
    [StructLayout(LayoutKind.Sequential)]
    public struct KeyValuePair
    {
        public IntPtr Key;
        public IntPtr Value;
    }

    // 解析配置
    public static void ParseConfig(string config)
    {
        if (string.IsNullOrEmpty(config))
        {
            throw new ArgumentException("Configuration string cannot be null or empty.");
        }

        int result = parse_config(config);
        if (result < 0)
        {
            throw new Exception(GetErrorMessage());
        }
    }

    // 启动网络实例
    public static void RunNetworkInstance(string config)
    {
        if (string.IsNullOrEmpty(config))
        {
            throw new ArgumentException("Configuration string cannot be null or empty.");
        }

        int result = run_network_instance(config);
        if (result < 0)
        {
            throw new Exception(GetErrorMessage());
        }
    }

    // 保留网络实例
    public static void RetainNetworkInstances(string[] instanceNames)
    {
        IntPtr[] namePointers = null;
        IntPtr namesPtr = IntPtr.Zero;

        try
        {
            if (instanceNames != null && instanceNames.Length > 0)
            {
                namePointers = new IntPtr[instanceNames.Length];
                for (int i = 0; i < instanceNames.Length; i++)
                {
                    if (string.IsNullOrEmpty(instanceNames[i]))
                    {
                        throw new ArgumentException("Instance name cannot be null or empty.");
                    }
                    namePointers[i] = Marshal.StringToHGlobalAnsi(instanceNames[i]);
                }

                namesPtr = Marshal.AllocHGlobal(Marshal.SizeOf<IntPtr>() * namePointers.Length);
                Marshal.Copy(namePointers, 0, namesPtr, namePointers.Length);
            }

            int result = retain_network_instance(namesPtr, instanceNames?.Length ?? 0);
            if (result < 0)
            {
                throw new Exception(GetErrorMessage());
            }
        }
        finally
        {
            if (namePointers != null)
            {
                foreach (var ptr in namePointers)
                {
                    if (ptr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(ptr);
                    }
                }
            }

            if (namesPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(namesPtr);
            }
        }
    }

    // 收集网络信息
    public static KeyValuePair<string, string>[] CollectNetworkInfos(int maxLength)
    {
        IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<KeyValuePair>() * maxLength);
        try
        {
            int count = collect_network_infos(buffer, maxLength);
            if (count < 0)
            {
                throw new Exception(GetErrorMessage());
            }

            var result = new KeyValuePair<string, string>[count];
            for (int i = 0; i < count; i++)
            {
                var kv = Marshal.PtrToStructure<KeyValuePair>(buffer + i * Marshal.SizeOf<KeyValuePair>());
                string key = Marshal.PtrToStringAnsi(kv.Key);
                string value = Marshal.PtrToStringAnsi(kv.Value);

                // 释放由 FFI 分配的字符串内存
                free_string(kv.Key);
                free_string(kv.Value);

                result[i] = new KeyValuePair<string, string>(key, value);
            }

            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    // 获取错误信息
    private static string GetErrorMessage()
    {
        get_error_msg(out IntPtr errorMsgPtr);
        if (errorMsgPtr == IntPtr.Zero)
        {
            return "Unknown error";
        }

        string errorMsg = Marshal.PtrToStringAnsi(errorMsgPtr);
        free_string(errorMsgPtr); // 释放错误信息字符串
        return errorMsg;
    }
}
```

---

# 四、使用示例

## 1. 启动网络实例

```csharp
string config = @"
inst_name = ""demo""
network = ""test_network""
";

EasyTierFFI.ParseConfig(config);
EasyTierFFI.RunNetworkInstance(config);
```

---

## 2. 推荐后台线程轮询状态

```csharp
using System.Threading;
using System.Threading.Tasks;

var cts = new CancellationTokenSource();

Task.Run(async () =>
{
    while (!cts.Token.IsCancellationRequested)
    {
        var infos =
            EasyTierFFI.CollectNetworkInfos(10);

        foreach (var kv in infos)
        {
            Console.WriteLine(
                $"{kv.Key} -> {kv.Value}");
        }

        await Task.Delay(1000);
    }
});
```

建议：

- 轮询间隔 500~1000ms
- 不要在 UI 主线程调用
- 使用 CancellationToken 控制停止

---

## 3. 保留实例

```csharp
EasyTierFFI.RetainNetworkInstances(
    new[] { "demo" });
```

---

# 五、错误处理机制

所有函数返回值 < 0 时：

- 调用 get_error_msg
- 使用完必须调用 free_string 释放

封装类已自动处理。

---

# 六、内存管理规则

| 类型 | 分配方 | 释放方 |
|------|--------|--------|
| 输入字符串 | C# | C# |
| 错误字符串 | Rust | C# |
| collect 返回 key/value | Rust | C# |

原则：

> Rust 分配的字符串必须调用 free_string 释放。

---

# 七、动态库加载

Windows：

将 easytier_ffi.dll 放在：

- exe 同目录
- 或 PATH 目录

Linux：

```bash
export LD_LIBRARY_PATH=.
```

macOS：

```bash
export DYLD_LIBRARY_PATH=.
```

---

# 八、鸣谢

本项目基于：

https://github.com/EasyTier/EasyTier

感谢原仓库作者及所有贡献者构建了优秀的 P2P 网络系统。

本仓库仅进行：

- FFI 二次封装
- 多语言调用例子
- 自动构建跨平台动态库

向原作者致以诚挚敬意与感谢。
