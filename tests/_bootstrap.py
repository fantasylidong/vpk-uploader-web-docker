"""测试用的一次性环境引导。

`app.main` 在导入时就把 DATA_DIR、TMP_DIR、LAN 配置固化成模块常量，所以同一个进程里
只有第一次导入生效。多个测试模块各自设置环境变量再导入的话，先后顺序不同结果就不同。
统一从这里取环境，谁先导入都是同一套配置。
"""

import atexit
import os
import shutil
import tempfile

DATA_DIR = tempfile.mkdtemp(prefix="vpk-uploader-test-")

os.environ.setdefault("DATA_DIR", DATA_DIR)
os.environ.setdefault("TMP_DIR", os.path.join(DATA_DIR, "tmp"))
os.environ.setdefault("LAN_NODE_ID", "node-b")
os.environ.setdefault("LAN_GROUP", "room-1")
os.environ.setdefault("LAN_PEER_API_TOKEN", "b" * 64)
os.environ.setdefault("LAN_PEER_ALLOWED_CIDRS", "10.20.0.0/24")
os.environ.setdefault("LAN_DISK_RESERVE_MB", "0")
os.environ.setdefault("CHUNK_UPLOAD_DISK_RESERVE_MB", "0")

# 真正在用的目录以环境变量为准：别的模块可能已经先把它设过了。
DATA_DIR = os.environ["DATA_DIR"]
TMP_DIR = os.environ["TMP_DIR"]

# 进程退出时再删。挂在某个 TestCase 的 tearDownClass 上会被每个子类各执行一次，
# 第一个测试类结束就会删掉后面还要用的数据目录。
atexit.register(shutil.rmtree, DATA_DIR, True)
