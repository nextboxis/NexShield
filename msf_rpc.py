import os
import logging

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    MsfRpcClient = None

logger = logging.getLogger(__name__)

MSF_PASSWORD = os.environ.get("MSF_PASSWORD", "nexshield")
MSF_HOST = os.environ.get("MSF_HOST", "127.0.0.1")
def _get_msf_port() -> int:
    raw = os.environ.get("MSF_PORT", "55553")
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 55553

MSF_PORT = _get_msf_port()

def get_client():
    """
    Instantiate and return a Metasploit RPC client instance.
    Attempts SSL first, falls back to plaintext if SSL fails.
    """
    if not MsfRpcClient:
        raise RuntimeError("pymetasploit3 is not installed. Run: pip install pymetasploit3")
    try:
        return MsfRpcClient(MSF_PASSWORD, server=MSF_HOST, port=MSF_PORT, ssl=True)
    except Exception as e:
        try:
            return MsfRpcClient(MSF_PASSWORD, server=MSF_HOST, port=MSF_PORT, ssl=False)
        except Exception as e2:
            logger.error(f"MSF RPC connection error: {e2}")
            raise ConnectionError(f"Failed to connect to MSF RPC on {MSF_HOST}:{MSF_PORT}. Is msfrpcd running?") from e2

def execute_exploit(host: str, module_name: str, lhost: str = "eth0") -> dict:
    """
    Connect to msfrpcd and execute the specified exploit module against the target host.
    """
    try:
        client = get_client()
        logger.info("Connected to MSF RPC. Loading module: %s", module_name)
        
        try:
            exploit = client.modules.use('exploit', module_name.replace("exploit/", ""))
        except Exception as mod_err:
            logger.debug("Failed to load as exploit (%s), trying auxiliary", mod_err)
            exploit = client.modules.use('auxiliary', module_name.replace("auxiliary/", ""))

        if 'RHOSTS' in exploit.options:
            exploit['RHOSTS'] = host
            
        if 'LHOST' in exploit.options:
            exploit['LHOST'] = lhost
            
        logger.info("Executing %s against %s...", module_name, host)
        
        job_info = exploit.execute()
        
        job_id = job_info.get("job_id") if isinstance(job_info, dict) else None
        uuid = job_info.get("uuid") if isinstance(job_info, dict) else None
        msg = f"Exploit launched. Job ID: {job_id}" if job_id is not None else f"Exploit launched with result: {job_info}"

        return {
            "status": "success",
            "job_id": job_id,
            "uuid": uuid,
            "message": msg,
        }
        
    except Exception as e:
        logger.error("Exploit execution failed: %s", e)
        if isinstance(e, (ConnectionError, RuntimeError)):
            msg = str(e)
        else:
            msg = "An internal error occurred during exploit execution."
        return {
            "status": "error",
            "message": msg
        }
