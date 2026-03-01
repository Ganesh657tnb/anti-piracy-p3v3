import streamlit as st
import os, sqlite3, tempfile, subprocess, wave
import numpy as np
import bcrypt
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# ================= CONFIG =================
DB_NAME = "guardian_app1.db"
UPLOAD_DIR = "master_videos"
SECRET_KEY = b"SixteenByteKey!!"   # AES-128
GAIN = 0.006

# watermark windows (start_sec, duration_sec)
WM_SEGMENTS = [(10,3), (40,3), (70,3)]

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
    uid = uid.zfill(8)
    ctr = Counter.new(128)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)
    enc = cipher.encrypt(uid.encode())
    return "".join(format(b, "08b") for b in enc)

# ================= DSSS =================
def pn_sequence(n):
    np.random.seed(42)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

def embed_dsss(audio, bits):
    pn = pn_sequence(len(audio))
    spb = len(audio) // len(bits)
    wm = np.zeros(len(audio))

    for i,b in enumerate(bits):
        val = 1 if b=="1" else -1
        wm[i*spb:(i+1)*spb] = val * pn[i*spb:(i+1)*spb]

    rms = np.sqrt(np.mean(audio**2))
    strength = GAIN * rms if rms > 0.001 else 0
    return np.clip(audio + strength*wm, -32768, 32767)

# ================= WATERMARK CORE =================
def watermark_video(video_path, user_id):
    bits = encrypt_uid(str(user_id))

    with tempfile.TemporaryDirectory() as tmp:
        wav_full = os.path.join(tmp, "full.wav")
        wav_out = os.path.join(tmp, "wm.wav")
        out_vid = os.path.join(tmp, "final.mp4")

        # extract FULL audio
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

        # embed watermark only at selected windows
        for start,dur in WM_SEGMENTS:
            s = int(start * sr)
            e = int((start+dur) * sr)
            if e <= len(audio):
                audio[s:e] = embed_dsss(audio[s:e], bits)

        with wave.open(wav_out, 'wb') as w:
            w.setparams(params)
            w.writeframes(audio.astype(np.int16).tobytes())

        # merge FULL video + FULL audio
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

# ================= STREAMLIT UI =================
def main():
    st.set_page_config("Guardian App-1","🛡️",layout="wide")
    init_db()

    if "uid" not in st.session_state:
        st.session_state.uid = None

    st.title("🛡️ Guardian – Secure Video Distribution")

    # ---------- AUTH ----------
    if not st.session_state.uid:
        c1,c2 = st.columns(2)

        with c1:
            st.subheader("Login")
            u = st.text_input("Username", key="l_u")
            p = st.text_input("Password", type="password", key="l_p")
            if st.button("Login", key="l_b"):
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
            ru = st.text_input("Username", key="r_u")
            rp = st.text_input("Password", type="password", key="r_p")
            re = st.text_input("Email", key="r_e")
            rph = st.text_input("Phone", key="r_ph")
            if st.button("Register", key="r_b"):
                try:
                    h = bcrypt.hashpw(rp.encode(), bcrypt.gensalt())
                    conn = sqlite3.connect(DB_NAME)
                    conn.execute(
                        "INSERT INTO users(username,password,email,phone) VALUES(?,?,?,?)",
                        (ru,h,re,rph)
                    )
                    conn.commit()
                    conn.close()
                    st.success("Registered! Login now.")
                except:
                    st.error("Username exists")
        return

    # ---------- LOGGED ----------
    st.sidebar.success(f"User ID: {st.session_state.uid}")
    if st.sidebar.button("Logout"):
        st.session_state.uid = None
        st.rerun()

    tab1,tab2,tab3 = st.tabs(["📤 Upload","📥 Download","👥 Users"])

    with tab1:
        up = st.file_uploader("Upload video", type=["mp4","mkv","mov"])
        if up and st.button("Upload"):
            path = os.path.join(UPLOAD_DIR, up.name)
            with open(path,"wb") as f:
                f.write(up.read())
            conn = sqlite3.connect(DB_NAME)
            conn.execute(
                "INSERT INTO videos(filename,uploader) VALUES(?,?)",
                (up.name, st.session_state.uid)
            )
            conn.commit()
            conn.close()
            st.success("Uploaded")

    with tab2:
        conn = sqlite3.connect(DB_NAME)
        vids = conn.execute("SELECT filename FROM videos").fetchall()
        conn.close()

        for (v,) in vids:
            if st.button(f"Download {v}", key=v):
                with st.spinner("Embedding watermark…"):
                    data = watermark_video(
                        os.path.join(UPLOAD_DIR,v),
                        st.session_state.uid
                    )
                    st.download_button(
                        "Download",
                        data,
                        file_name=f"secured_{v}",
                        mime="video/mp4"
                    )

    with tab3:
        conn = sqlite3.connect(DB_NAME)
        users = conn.execute(
            "SELECT id,username,email,phone FROM users"
        ).fetchall()
        conn.close()
        st.table(users)

if __name__ == "__main__":
    main()
