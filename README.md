# 🔍 Automated Recon Framework + AI Analysis with Groq + LangChain

A complete reconnaissance pipeline with AI-powered reporting.

# Banner

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
           Automated Recon + AI

# Overview

This project is a full bug bounty reconnaissance framework that automates:  

- Subdomain enumeration (Subfinder & assetfinder)  
- Alive checking (httprobe)  
- HTTP fingerprinting (httpx)  
- JS/parameter extraction  
- Wayback discovery (waybackurls)  
- Subdomain takeover checks (subzy)  
- Crawling & file extraction (katana)  
- Secret detection (secretfinder)  
- And finally…  

# 🤖 AI-Powered Analysis using Groq + LangChain  

The script generates an advanced Markdown report that includes:

✔ HTTPX Analysis  
✔ Parameter & URL Attack Surface Insights  
✔ Next-Step Recommendations  
✔ Business logic mapping of subdomains  
✔ CVE-based checks based on server type  


# AI do

Script analyzes:  
1. HTTPX Output  
2. URL & Parameter Analysis  
3. Combined Next-Steps Strategy  

Requirements  

Install dependencies:  
`pip install langchain_groq langchain-core python-dotenv`

Set environment variable:
`export GROQ_API_KEY="your_api_key"`


# ⚙️ Recon Script Usage

`./recon.sh target.com output/`


# Screenshot

![SS1](/home/kali/Pictures/Selection_001.avif)

![SS2](/home/kali/Pictures/Selection_002.avif)


This project is intended for authorized security testing only.
The creator is not responsible for any misuse.


