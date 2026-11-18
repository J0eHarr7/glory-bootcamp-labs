FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y iputils-ping dnsutils && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN echo "CTF{cmdi_l1_n41v3_sh3ll_c0nc4t}" > /flag1.txt \
 && echo "CTF{cmdi_l2_p1p3_byp4ss3d_bl4ckl1st}" > /flag2.txt \
 && echo "CTF{cmdi_l3_1fs_4nd_nl_byp4ss}" > /flag3.txt \
 && chmod 444 /flag1.txt /flag2.txt /flag3.txt \
 && useradd -m ctf && chown -R ctf /app
USER ctf
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "app:app"]
