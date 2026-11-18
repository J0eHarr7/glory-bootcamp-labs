FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN echo "J0eHarr7{ssti_l1_r4w_j1nj4_1nj3ct10n}" > /flag1.txt \
 && echo "J0eHarr7{ssti_l2_bl4ckl1st_byp4ss3d}" > /flag2.txt \
 && echo "J0eHarr7{ssti_l3_attr_ch41n_g4dg3t_byp4ss}" > /flag3.txt \
 && chmod 444 /flag1.txt /flag2.txt /flag3.txt \
 && useradd -m ctf && chown -R ctf /app
USER ctf
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "app:app"]
