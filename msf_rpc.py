import os
import logging

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    MsfRpcClient = None

logger = logging.getLogger(__name__)

# Default config for MSF RPC
MSF_PASSWORD = os.environ.get("MSF_PASSWORD", "nexshield")
MSF_HOST = os.environ.get("MSF_HOST", "127.0.0.1")
MSF_PORT = int(os.environ.get("MSF_PORT", "55553"))

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
        # Retry without SSL as fallback
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
        
        # Load the exploit module
        try:
            exploit = client.modules.use('exploit', module_name.replace("exploit/", ""))
        except Exception as mod_err:
            # Maybe it's an auxiliary module
            logger.debug("Failed to load as exploit (%s), trying auxiliary", mod_err)
            exploit = client.modules.use('auxiliary', module_name.replace("auxiliary/", ""))

        # Set standard payload/options
        if 'RHOSTS' in exploit.options:
            exploit['RHOSTS'] = host
            
        # Often needed for reverse shells
        if 'LHOST' in exploit.options:
            exploit['LHOST'] = lhost
            
        logger.info("Executing %s against %s...", module_name, host)
        
        # Execute asynchronously
        job_info = exploit.execute()
        
        return {
            "status": "success",
            "job_id": job_info.get("job_id"),
            "uuid": job_info.get("uuid"),
            "message": f"Exploit launched. Job ID: {job_info.get('job_id')}"
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
