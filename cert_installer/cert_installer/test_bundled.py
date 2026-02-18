import os
import sys

def get_script_dir():
    if getattr(sys, "frozen", False):
        return sys._MEIPASS
    else:
        return os.path.dirname(os.path.abspath(__file__))

script_dir = get_script_dir()
print(f"Script dir: {script_dir}")
print(f"Is frozen: {getattr(sys, 'frozen', False)}")
print("\nFiles in script_dir:")
if os.path.exists(script_dir):
    for item in sorted(os.listdir(script_dir)):
        full_path = os.path.join(script_dir, item)
        if os.path.isfile(full_path):
            size = os.path.getsize(full_path)
            print(f"  {item} ({size} bytes)")
        elif "mitm" in item.lower() or "chrome" in item.lower():
            print(f"  {item}/ (directory)")

input("\nPress Enter to exit...")
