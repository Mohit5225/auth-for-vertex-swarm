"""Reproduce oauth/start HTML template build."""
from types import SimpleNamespace

settings = SimpleNamespace(
    neon_auth_base_url="https://ep-jolly-feather-aiaavjnk.neonauth.c-4.us-east-1.aws.neon.tech/neondb/auth"
)
neon_callback_url = "https://auth-for-vertex-swarm.onrender.com/oauth/callback?transaction=abc123"

html = f"""
    <!DOCTYPE html>
    <html>
    <body>
        <script type="module">
            import {{ createAuthClient }} from "https://esm.sh/@neondatabase/auth@0.4.2-beta?bundle";
            import {{ BetterAuthVanillaAdapter }} from "https://esm.sh/@neondatabase/auth@0.4.2-beta/vanilla/adapters?bundle";
            const authClient = createAuthClient("{settings.neon_auth_base_url}", {{
                adapter: BetterAuthVanillaAdapter({{
                    fetchOptions: {{ credentials: "include" }},
                }}),
            }});
            authClient.signIn.social({{
                provider: "google",
                callbackURL: "{neon_callback_url}"
            }});
        </script>
    </body>
    </html>
"""
print("OK", len(html))
