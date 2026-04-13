from rich.console import Console
from rich.panel import Panel

console = Console()

def print_briefing(title, happening, fallback=None, action=None, command=None, style="blue"):
    """Renders a Tactical Intelligence Briefing in the terminal."""
    content = f"[bold white]Situation:[/bold white] [dim]{happening}[/dim]\n"
    
    if fallback:
        content += f"[bold yellow]Fallback:[/bold yellow] [dim]{fallback}[/dim]\n"
    if action:
        content += f"[bold green]Operator Action:[/bold green] [dim]{action}[/dim]\n"
    if command:
        content += f"[bold cyan]Manual Verification:[/bold cyan] {command}"
        
    console.print(Panel(content, title=f"[bold {style}]Intelligence Brief: {title}[/bold {style}]", border_style=style, expand=False))
