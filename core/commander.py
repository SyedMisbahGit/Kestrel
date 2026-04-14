import requests
import sys
import base64
from rich.console import Console
from rich.table import Table

console = Console()

class KestrelCommander:
    def __init__(self, token, owner, repo):
        self.token = token
        self.owner = owner
        self.repo = repo
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }

    def trigger_strike(self):
        """Forces GitHub to start the workflow immediately."""
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/workflows/strike.yml/dispatches"
        r = requests.post(url, json={"ref": "main"}, headers=self.headers)
        if r.status_code == 204:
            console.print("[bold green]  + SIGNAL SENT:[/bold green] GitHub is waking up Kestrel.")
        else:
            console.print(f"[bold red]  ! FAILED:[/bold red] {r.text}")

    def add_target(self, new_domain):
        """Fetches targets.txt, appends a domain, and pushes it back to GitHub."""
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/contents/targets.txt"
        
        # 1. Get current file
        r = requests.get(url, headers=self.headers)
        if r.status_code != 200:
            console.print("[red]Could not find targets.txt on GitHub.[/red]")
            return

        data = r.json()
        sha = data['sha']
        current_content = base64.b64decode(data['content']).decode('utf-8')
        
        if new_domain in current_content:
            console.print(f"[yellow]Target {new_domain} already in queue.[/yellow]")
            return

        # 2. Append and Update
        new_content = current_content.strip() + f"\n{new_domain}\n"
        payload = {
            "message": f"Commander: Added {new_domain} to queue",
            "content": base64.b64encode(new_content.encode()).decode(),
            "sha": sha
        }
        
        r = requests.put(url, json=payload, headers=self.headers)
        if r.status_code == 200:
            console.print(f"[bold green]  + QUEUE UPDATED:[/bold green] {new_domain} is now in the 24/7 cycle.")
        else:
            console.print(f"[red]Failed to update queue: {r.text}[/red]")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python core/commander.py <GITHUB_TOKEN> <OWNER> <REPO> <command> [domain]")
        sys.exit(1)

    cmd_center = KestrelCommander(sys.argv[1], sys.argv[2], sys.argv[3])
    action = sys.argv[4].lower()

    if action == "strike":
        cmd_center.trigger_strike()
    elif action == "add" and len(sys.argv) == 6:
        cmd_center.add_target(sys.argv[5])
    else:
        print("Invalid command. Use 'strike' or 'add <domain>'")
