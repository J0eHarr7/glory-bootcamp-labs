FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libxml2 libxslt1.1 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN printf "CTF{xx3_l1_cl4ss1c_f1l3_r3ad_ext3rn4l_3nt1ty}" > /flag1.txt \
 && printf "CTF_XXE_L2_BLIND_OOB_EXFIL_SUCCESS_1337" > /flag2.txt \
 && chmod 444 /flag1.txt /flag2.txt \
 && useradd -m ctf && chown -R ctf /app
USER ctf
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "app:app"]
