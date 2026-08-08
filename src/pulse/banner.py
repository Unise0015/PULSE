from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box

from pulse import __version__
from pulse.config import get_setting

console = Console()

UNICODE_SUPPORTED = True

def get_banner_content(wave_lines: list, fallback: bool = False) -> Panel:
    from pulse import __version__
    if fallback:
        ascii_logo = r"""
######   #    #  #       #####  ######
#     #  #    #  #       #      #     
######   #    #  #       #####  ##### 
#        #    #  #           #  #     
#         ####   ######  #####  ######"""
    else:
        ascii_logo = r"""
██████╗ ██╗   ██╗██╗     ███████╗███████╗
██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
██████╔╝██║   ██║██║     ███████╗█████╗  
██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
██║     ╚██████╔╝███████╗███████║███████╗
╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝"""

    wave_str = "\n".join(wave_lines)
    wave_text = Text(wave_str, style="bold color(202)")
    logo_text = Text(ascii_logo.lstrip("\n"), style="bold color(196)")
    title_text = Text("Package & Unified Lifecycle Security Engine", style="bold white")

    from rich.console import Group
    group = Group(
        Align.center(wave_text),
        Text(""), # Gap space
        Align.center(logo_text),
        Text(""), # Empty line
        Align.center(title_text)
    )

    return Panel(
        group,
        box=box.DOUBLE,
        border_style="color(196)",
        padding=(1, 2)
    )

def show_banner():
    """Display the interactive ASCII art banner for PULSE."""
    import time
    from rich.live import Live
    from pulse import __version__
    global UNICODE_SUPPORTED
    
    l1 = r"           /\       " * 3
    l2 = r"___  _/\__/  \  /\__" * 3
    l3 = r"   \/         \/    " * 3
    length = len(l1)
    
    wave_frames = []
    shift = 1
    num_frames = 20
    for i in range(num_frames):
        s = (i * shift) % length
        if s == 0:
            f1, f2, f3 = l1, l2, l3
        else:
            f1 = l1[-s:] + l1[:-s]
            f2 = l2[-s:] + l2[:-s]
            f3 = l3[-s:] + l3[:-s]
        wave_frames.append([f1, f2, f3])
    
    try:
        "██".encode(console.encoding or "ascii")
    except UnicodeEncodeError:
        UNICODE_SUPPORTED = False
        
    try:
        with Live(get_banner_content(wave_frames[0], fallback=not UNICODE_SUPPORTED), console=console, refresh_per_second=15) as live:
            for frame in wave_frames:
                live.update(get_banner_content(frame, fallback=not UNICODE_SUPPORTED))
                time.sleep(1/15.0)
    except Exception:
        UNICODE_SUPPORTED = False
        # Plain static fallback
        console.print(get_banner_content(wave_frames[0], fallback=True))
            
    # Check configurations
    nvd_key = get_setting("NVD_API_KEY")
    nvd_status = "Configured        (50 req/30s)" if nvd_key else "Not configured    (5 req/30s)"
    
    status_text = Text()
    status_text.append(f"  Version  : {__version__}\n", style="bold")
    status_text.append(f"  NVD Key  : {nvd_status}\n")
    status_text.append(f"  EPSS     : Active\n")
    status_text.append(f"  KEV      : Cached\n")
    
    console.print(status_text)
    console.print() # Empty line before menu
