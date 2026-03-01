import streamlit as st
import os, sqlite3, tempfile, subprocess, wave
import numpy as np
import bcrypt
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# ================= CONFIG =================
DB_NAME = "guardian_app1.db"
UPLOAD_DIR = "master_videos"
SECRET_KEY = b"SixteenByteKey!!"   # 16 bytes = AES-128
GAIN = 0.006

# Smart redundancy → 3 short audio segments
WM_SEGMENTS = [(10, 3), (40, 3), (70, 3)]  # (start_sec, duration_sec)

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB,
            email TEXT,
            phone TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            uploader INTEGER
        )
    """)

    conn.commit()
    conn.close()

# ================= CRYPTO =================
def encrypt_uid(uid: str) -> str:
    uid_fixed = uid.zfill(8)  # fixed length for DSSS stability
    ctr = Counter.new(128)    # ✅ FIXED (AES needs 128-bit counter)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)
    encrypted = cipher.encrypt(uid_fixed.encode())

    # bytes → binary string
    return "".join(format(b, "08b") for b in encrypted)

# ================= DSSS =================
def pn_sequence(n):
    np.random.seed(42)
    return (np.random.randint(0, 2, n) * 2 - 1).astype(np.float32)

def embed_dsss(audio, bits):
    pn = pn_sequence(len(audio))
    samples_per_bit = len(audio) // len(bits)
    watermark = np.zeros(len(audio))

    for i, bit in enumerate(bits):
        val = 1 if bit == "1" else -1
        watermark[i*samples_per_bit:(i+1)*samples_per_bit] = (
            val * pn[i*samples_per_bit:(i+1)*samples_per_bit]
        )

    rms = np.sqrt(np.mean(audio ** 2))
    strength = GAIN * rms if rms > 0.001 else 0

    return np.clip(audio + strength * watermark, -32768, 32767)

# ================= FFMPEG =================
def run(cmd):
    subprocess.run(cmd, check=True, capture_output=True)

# ================= WATERMARK CORE =================
def watermark_video(video_path, user_id):
    bits = encrypt_uid(str(user_id))

    with tempfile.TemporaryDirectory() as tmp:
        current_video = video_path

        for idx, (start, dur) in enumerate(WM_SEGMENTS):
            wav_in = os.path.join(tmp, f"in_{idx}.wav")
            wav_out = os.path.join(tmp, f"out_{idx}.wav")
            out_vid = os.path.join(tmp, f"out_{idx}.mp4")

            # Extract short audio segment
            run([
                "ffmpeg", "-y", "-i", current_video,
                "-ss", str(start), "-t", str(dur),
                "-vn", "-ac", "1", "-ar", "44100",
                wav_in
            ])

            with wave.open(wav_in, 'rb') as w:
                params = w.getparams()
                audio = np.frombuffer(
                    w.readframes(w.getnframes()),
                    dtype=np.int16
                ).astype(np.float32)

            if len(audio) < 1000:
                continue

            wm_audio = embed_dsss(audio, bits)

            with wave.open(wav_out, 'wb') as w:
                w.setparams(params)
                w.writeframes(wm_audio.astype(np.int16).tobytes())

            # Merge back
            run([
                "ffmpeg", "-y",
                "-i", current_video,
                "-i", wav_out,
                "-map", "0:v",
                "-map", "1:a",
                "-c:v", "copy",
                "-c:a", "aac",
                "-shortest",
                out_vid
            ])

            current_video = out_vid

        with open(current_video, "rb") as f:
            return f.read()

# ================= STREAMLIT UI =================
def main():
    st.set_page_config("Guardian App-1", "🛡️", layout="wide")
    init_db()

    if "uid" not in st.session_state:
        st.session_state.uid = None

    st.title("🛡️ Guardian – Secure Video Distribution (App-1)")

    # ---------- AUTH ----------
    if not st.session_state.uid:
        c1, c2 = st.columns(2)

        with c1:
            st.subheader("Login")
            u = st.text_input("Username", key="login_user")
            p = st.text_input("Password", type="password", key="login_pass")

            if st.button("Login", key="login_btn"):
                conn = sqlite3.connect(DB_NAME)
                row = conn.execute(
                    "SELECT id, password FROM users WHERE username=?",
                    (u,)
                ).fetchone()
                conn.close()

                if row and bcrypt.checkpw(p.encode(), row[1]):
                    st.session_state.uid = row[0]
                    st.rerun()
                else:
                    st.error("Invalid credentials")

        with c2:
            st.subheader("Register")
            ru = st.text_input("Username", key="reg_user")
            rp = st.text_input("Password", type="password", key="reg_pass")
            re = st.text_input("Email", key="reg_email")
            rph = st.text_input("Phone Number", key="reg_phone")

            if st.button("Register", key="reg_btn"):
                if not (ru and rp and re and rph):
                    st.error("All fields required")
                else:
                    try:
                        hashed = bcrypt.hashpw(rp.encode(), bcrypt.gensalt())
                        conn = sqlite3.connect(DB_NAME)
                        conn.execute(
                            "INSERT INTO users(username,password,email,phone) VALUES(?,?,?,?)",
                            (ru, hashed, re, rph)
                        )
                        conn.commit()
                        conn.close()
                        st.success("Registered successfully. Login now.")
                    except:
                        st.error("Username already exists")
        return

    # ---------- LOGGED IN ----------
    st.sidebar.success(f"User ID: {st.session_state.uid}")
    if st.sidebar.button("Logout", key="logout_btn"):
        st.session_state.uid = None
        st.rerun()

    tab1, tab2, tab3 = st.tabs(["📤 Upload", "📥 Download", "👥 Users"])

    # Upload
    with tab1:
        up = st.file_uploader(
            "Upload Master Video",
            type=["mp4", "mkv", "mov"],
            key="upload_file"
        )
        if up and st.button("Upload", key="upload_btn"):
            path = os.path.join(UPLOAD_DIR, up.name)
            with open(path, "wb") as f:
                f.write(up.read())

            conn = sqlite3.connect(DB_NAME)
            conn.execute(
                "INSERT INTO videos(filename,uploader) VALUES(?,?)",
                (up.name, st.session_state.uid)
            )
            conn.commit()
            conn.close()
            st.success("Video uploaded successfully")

    # Download
    with tab2:
        conn = sqlite3.connect(DB_NAME)
        vids = conn.execute("SELECT filename FROM videos").fetchall()
        conn.close()

        if not vids:
            st.info("No videos available")

        for v in vids:
            fname = v[0]
            if st.button(f"Download {fname}", key=f"dl_{fname}"):
                with st.spinner("Embedding encrypted watermark..."):
                    data = watermark_video(
                        os.path.join(UPLOAD_DIR, fname),
                        st.session_state.uid
                    )
                    st.download_button(
                        "Click to Download",
                        data,
                        file_name=f"secured_{fname}",
                        mime="video/mp4",
                        key=f"final_dl_{fname}"
                    )

    # Users
    with tab3:
        conn = sqlite3.connect(DB_NAME)
        users = conn.execute(
            "SELECT id, username, email, phone FROM users"
        ).fetchall()
        conn.close()

        st.subheader("Registered Users")
        st.table(users)

if __name__ == "__main__":
    main()
