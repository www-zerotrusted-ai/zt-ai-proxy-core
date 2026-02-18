"""
ZTProxy Certificate Uninstaller
Removes mitmproxy CA certificate from Windows Trusted Root store
"""
import os
import sys
import subprocess

def uninstall_certificate():
    """Remove mitmproxy certificate from Windows Trusted Root store"""
    print("\n📜 Removing mitmproxy CA certificate...")
    
    # Certificate common name used by mitmproxy
    cert_name = "mitmproxy"
    
    try:
        # Remove from user's Trusted Root store
        result = subprocess.run([
            "certutil", "-user", "-delstore", "Root", cert_name
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Certificate removed successfully")
            return True
        else:
            # Check if it was just "not found" which is also success
            if "not found" in result.stderr.lower() or "cannot find" in result.stderr.lower():
                print("ℹ️  Certificate was not installed (already removed)")
                return True
            else:
                print(f"⚠️  Certificate removal: {result.stderr}")
                return False
            
    except FileNotFoundError:
        print("❌ certutil not found. Please ensure you're running on Windows.")
        return False
    except Exception as e:
        print(f"❌ Error removing certificate: {e}")
        return False

def main():
    print("=" * 60)
    print("  ZTProxy Certificate Uninstaller")
    print("=" * 60)
    
    # Confirm uninstall
    print("\nThis will remove the mitmproxy CA certificate from your")
    print("Trusted Root Certification Authorities store.")
    print("\nAfter removal, HTTPS interception will no longer work.")
    
    response = input("\nContinue? (y/N): ").strip().lower()
    
    if response not in ['y', 'yes']:
        print("Uninstall cancelled")
        input("\nPress Enter to exit...")
        return False
    
    # Uninstall certificate
    success = uninstall_certificate()
    
    # Summary
    print("\n" + "=" * 60)
    if success:
        print("✅ Certificate uninstalled successfully!")
        print("   You may need to restart your browser.")
    else:
        print("⚠️  Uninstall completed with warnings")
    print("=" * 60)
    
    input("\nPress Enter to exit...")
    return success

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nUninstall cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
        sys.exit(1)
