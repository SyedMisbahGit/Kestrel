import requests
import sys

def trigger_manual_strike(github_token, repo_owner, repo_name):
    """Sends a signal to GitHub to start Kestrel immediately."""
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/dispatches"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {"event_type": "manual_strike"}
    r = requests.post(url, json=data, headers=headers)
    if r.status_code == 204:
        print("Done! GitHub is waking up Kestrel for a manual strike.")
    else:
        print(f"Failed: {r.text}")

if __name__ == "__main__":
    # Usage: python core/bot_control.py <TOKEN> <OWNER> <REPO>
    trigger_manual_strike(sys.argv[1], sys.argv[2], sys.argv[3])
