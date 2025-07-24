def create_dependency_checker():
    checker_code = '''
import sys
import os

print("MonsterApps Dependency Checker")
print("=" * 40)

# Check Python version
print(f"Python version: {sys.version}")
if sys.version_info < (3, 8):
    print("⚠️  WARNING: Python 3.8+ recommended")
else:
    print("✓ Python version OK")

print()

# Check required modules
required = {
    "tkinter": "GUI framework (usually built-in)",
    "mysql.connector": "pip install mysql-connector-python",
    "cryptography": "pip install cryptography", 
    "PIL": "pip install Pillow",
    "cv2": "pip install opencv-python",
    "numpy": "pip install numpy",
    "requests": "pip install requests"
}

missing = []
print("Module Check:")
for module, install_cmd in required.items():
    try:
        if module == "PIL":
            from PIL import Image
        elif module == "cv2":
            import cv2
        else:
            __import__(module)
        print(f"✓ {module}")
    except ImportError:
        print(f"✗ {module} - {install_cmd}")
        missing.append((module, install_cmd))

print()

if missing:
    print("MISSING MODULES:")
    print("Run these commands to install:")
    for module, cmd in missing:
        print(f"  {cmd}")
    print()
    
    # Try to install automatically
    choice = input("Try to install missing modules automatically? (y/n): ")
    if choice.lower() == 'y':
        import subprocess
        for module, cmd in missing:
            if "pip install" in cmd:
                pkg = cmd.replace("pip install ", "")
                print(f"Installing {pkg}...")
                subprocess.run([sys.executable, "-m", "pip", "install", pkg])
else:
    print("✓ All required modules found!")

print()

# Check directories
dirs = ["monsterapps_data", "monsterapps_data/mods", "monsterapps_data/installed_apps"]
print("Directory Check:")
for d in dirs:
    if os.path.exists(d):
        print(f"✓ {d}")
    else:
        print(f"✗ {d} - will be created automatically")
        os.makedirs(d, exist_ok=True)
        print(f"  Created {d}")

print()
print("Dependency check complete!")
input("Press Enter to exit...")
'''
    
    with open("check_deps.py", "w") as f:
        f.write(checker_code)
    
    print("Created check_deps.py - run this first on the target computer!")
