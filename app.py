import streamlit as st
import os, sqlite3, tempfile, subprocess, wave, hashlib
import numpy as np
import bcrypt
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# ================= CONFIG =================
DB_NAME = "guardian.db"
UPLOAD_DIR = "master_videos"
SECRET_KEY = b"SixteenByteKey!!"
GAIN = 0.006

WM_SEGMENTS = [(10,3), (40,3), (70,3)]
BIT_LEN = 128  # nonce(8) + ciphertext(8)

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB,
            email TEXT,
            phone TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS videos(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            uploader INTEGER
        )
    """)
    conn.commit()
    conn.close()

# ================= CRYPTO =================
def encrypt_uid(uid):
    uid_bytes = uid.zfill(8).encode()
    nonce = os.urandom(8)
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(uid_bytes)
    return nonce, ciphertext

# ================= PN =================
def pn_sequence(n, nonce):
    seed_material = hashlib.sha256(SECRET_KEY + nonce).digest()
    seed = int.from_bytes(seed_material[:4], "big")
    np.random.seed(seed)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

# ================= DSSS =================
def embed_dsss(audio, bits, nonce):
    pn = pn_sequence(len(audio), nonce)
    spb = len(audio) // len(bits)

    wm = np.zeros(len(audio))
    for i,b in enumerate(bits):
        val = 1 if b=="1" else -1
        wm[i*spb:(i+1)*spb] = val * pn[i*spb:(i+1)*spb]

    rms = np.sqrt(np.mean(audio**2))
    strength = GAIN * rms if rms > 0.001 else 0
    return np.clip(audio + strength*wm, -32768, 32767)

# ================= WATERMARK =================
def watermark_video(video_path, user_id):
    nonce, ciphertext = encrypt_uid(str(user_id))
    payload = nonce + ciphertext
    bits = "".join(format(b, "08b") for b in payload)

    with tempfile.TemporaryDirectory() as tmp:
        wav_full = os.path.join(tmp, "full.wav")
        wav_out = os.path.join(tmp, "wm.wav")
        out_vid = os.path.join(tmp, "final.mp4")

        subprocess.run([
            "ffmpeg","-y","-i",video_path,
            "-vn","-ac","1","-ar","44100",
            wav_full
        ], check=True)

        with wave.open(wav_full, 'rb') as w:
            params = w.getparams()
            audio = np.frombuffer(
                w.readframes(w.getnframes()),
                dtype=np.int16
            ).astype(np.float32)

        sr = params.framerate

        for start,dur in WM_SEGMENTS:
            s = int(start * sr)
            e = int((start+dur) * sr)
            if e <= len(audio):
                audio[s:e] = embed_dsss(audio[s:e], bits, nonce)

        with wave.open(wav_out, 'wb') as w:
            w.setparams(params)
            w.writeframes(audio.astype(np.int16).tobytes())

        subprocess.run([
            "ffmpeg","-y",
            "-i",video_path,
            "-i",wav_out,
            "-map","0:v",
            "-map","1:a",
            "-c:v","copy",
            "-c:a","aac",
            out_vid
        ], check=True)

        with open(out_vid, "rb") as f:
            return f.read()

# ================= STREAMLIT =================
def main():
    st.set_page_config("Guardian App-1","🛡️",layout="wide")
    init_db()

    if "uid" not in st.session_state:
        st.session_state.uid = None

    st.title("🛡️ Guardian – Secure Distribution")

    if not st.session_state.uid:
        c1,c2 = st.columns(2)

        with c1:
            st.subheader("Login")
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            if st.button("Login"):
                conn = sqlite3.connect(DB_NAME)
                r = conn.execute(
                    "SELECT id,password FROM users WHERE username=?",(u,)
                ).fetchone()
                conn.close()
                if r and bcrypt.checkpw(p.encode(), r[1]):
                    st.session_state.uid = r[0]
                    st.rerun()
                else:
                    st.error("Invalid login")

        with c2:
            st.subheader("Register")
            ru = st.text_input("Username", key="r1")
            rp = st.text_input("Password", type="password", key="r2")
            re = st.text_input("Email")
            rph = st.text_input("Phone")
            if st.button("Register"):
                try:
                    h = bcrypt.hashpw(rp.encode(), bcrypt.gensalt())
                    conn = sqlite3.connect(DB_NAME)
                    conn.execute(
                        "INSERT INTO users(username,password,email,phone) VALUES(?,?,?,?)",
                        (ru,h,re,rph)
                    )
                    conn.commit()
                    conn.close()
                    st.success("Registered!")
                except:
                    st.error("Username exists")
        return

    st.sidebar.success(f"User ID: {st.session_state.uid}")
    if st.sidebar.button("Logout"):
        st.session_state.uid = None
        st.rerun()

    up = st.file_uploader("Upload master video", type=["mp4","mkv","mov"])
    if up and st.button("Upload & Embed Watermark"):
        path = os.path.join(UPLOAD_DIR, up.name)
        with open(path,"wb") as f:
            f.write(up.read())

        data = watermark_video(path, st.session_state.uid)

        st.download_button(
            "Download Watermarked Copy",
            data,
            file_name=f"secured_{up.name}",
            mime="video/mp4"
        )

if __name__ == "__main__":
    main()
