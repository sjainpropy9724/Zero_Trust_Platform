import streamlit as st
import pandas as pd
import psycopg2
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
import os

# --- CONFIGURATION ---
st.set_page_config(page_title="Admin SOC | Zero-Trust Platform", layout="wide", page_icon="🔐")
DB_URL = "postgresql://user:password@localhost:5432/mydatabase"

# Auto-refresh every 10 seconds (less aggressive to save load)
st_autorefresh(interval=10000, key="data_refresh")

# --- OPTIMIZED DATA LOADING (No more hanging!) ---
def get_db_connection():
    return psycopg2.connect(DB_URL)

def load_kpis():
    conn = get_db_connection()
    cur = conn.cursor()
    # Efficient COUNT queries that run in milliseconds
    cur.execute("SELECT COUNT(*) FROM users")
    user_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM files")
    file_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM activity_logs WHERE timestamp > NOW() - INTERVAL '24 HOURS'")
    events_24h = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM activity_logs WHERE status='DENIED_BY_POLICY' AND timestamp > NOW() - INTERVAL '24 HOURS'")
    blocks_24h = cur.fetchone()[0]
    conn.close()
    return user_count, file_count, events_24h, blocks_24h

def load_recent_logs(limit=50):
    conn = get_db_connection()
    # Only load the last N rows, not ALL rows
    query = f"""
        SELECT timestamp, username, action, status, ip_address, details 
        FROM activity_logs ORDER BY timestamp DESC LIMIT {limit}
    """
    df = pd.read_sql(query, conn)
    conn.close()
    return df

def load_users():
    conn = get_db_connection()
    query = "SELECT id, username, role, last_login FROM users ORDER BY id"
    df = pd.read_sql(query, conn)
    conn.close()
    return df

# --- SIDEBAR NAVIGATION ---
st.sidebar.title("🔐 Admin Console")
page = st.sidebar.radio("Navigate", ["Overview SOC", "User Management", "Threat Explorer"])

# --- PAGE 1: OVERVIEW SOC ---
if page == "Overview SOC":
    st.title("🛡️ Security Operations Center")
    
    # KPIs
    uc, fc, ev24, bl24 = load_kpis()
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Users", uc)
    k2.metric("Total Files Secured", fc)
    k3.metric("24h Events", ev24)
    k4.metric("24h Policy Blocks", bl24, delta_color="inverse")

    # Live Feed
    st.subheader("📝 Live Activity Feed (Last 50 Events)")
    st.dataframe(load_recent_logs(50), width='stretch', height=400)

# --- PAGE 2: USER MANAGEMENT (Fixes your Issue #1 & #3) ---
elif page == "User Management":
    st.title("👥 User Governance")
    
    users_df = load_users()
    
    # Role Update UI
    st.subheader("Manage Roles")
    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        user_to_mod = st.selectbox("Select User to Promote/Demote", users_df['username'].unique())
    with c2:
        new_role = st.selectbox("New Role", ["intern", "employee", "manager", "admin"])
    with c3:
        st.write("") # Spacer
        st.write("") # Spacer
        if st.button("Update Role 🆙"):
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE users SET role = %s WHERE username = %s", (new_role, user_to_mod))
            conn.commit()
            conn.close()
            st.success(f"Updated {user_to_mod} to {new_role}!")
            st.rerun()

    # User Table
    st.subheader("User Directory")
    # Highlight admins in red, managers in orange
    def highlight_roles(val):
        color = 'red' if val == 'admin' else 'orange' if val == 'manager' else 'white'
        return f'color: {color}; font-weight: bold'
    
    st.dataframe(
        users_df.style.map(highlight_roles, subset=['role']),
        width='stretch',
        height=500
    )

# --- PAGE 3: THREAT EXPLORER ---
elif page == "Threat Explorer":
    st.title("🚨 Threat Hunting")
    
    # 1. AGGREGATED VIEW (Fast, no massive data load needed)
    st.subheader("📊 Attack Surface Analysis")
    conn = get_db_connection()
    
    # SQL does the counting, very fast even for 1 million rows
    top_users_query = """
        SELECT username, action, COUNT(*) as count 
        FROM activity_logs 
        GROUP BY username, action 
        ORDER BY count DESC 
        LIMIT 20
    """
    top_users_df = pd.read_sql(top_users_query, conn)
    
    if not top_users_df.empty:
        fig = px.bar(top_users_df, x="username", y="count", color="action", 
                     title="Top 20 Most Active Users by Action Type", barmode='group')
        st.plotly_chart(fig, width='stretch')

    # 2. RAW DATA INSPECTOR (Only load small chunks when needed)
    st.markdown("---")
    st.subheader("🔍 Deep Dive Inspector")
    
    # Initialize session state for this view if it doesn't exist
    if 'show_logs' not in st.session_state:
        st.session_state.show_logs = False

    col1, col2 = st.columns(2)
    with col1:
        target_user = st.text_input("Filter by Username (Optional)")
    with col2:
        limit = st.slider("Max rows to fetch", 100, 1000, 500)

    # Toggle button
    if st.button("Toggle Raw Logs"):
        st.session_state.show_logs = not st.session_state.show_logs

    # Only run query and show data if state is True
    if st.session_state.show_logs:
        with st.spinner("Querying live database..."):
            query = f"SELECT * FROM activity_logs WHERE 1=1"
            params = []
            if target_user:
                query += " AND username = %s"
                params.append(target_user)
            query += f" ORDER BY timestamp DESC LIMIT {limit}"
            
            # Re-open connection just for this query
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            cols = [desc[0] for desc in cur.description]
            results = cur.fetchall()
            cur.close()
            conn.close()
            
            raw_df = pd.DataFrame(results, columns=cols)
            
        if not raw_df.empty:
            st.dataframe(raw_df, width='stretch')
            st.subheader(f"Timeline ({len(raw_df)} events)")
            fig2 = px.scatter(raw_df, x="timestamp", y="username", color="action", 
                            hover_data=['details', 'ip_address'])
            st.plotly_chart(fig2, width='stretch')
        else:
            st.warning("No logs found for these criteria.")
            
    conn.close()