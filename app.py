import os
import json
import hashlib
import mysql.connector
from flask import Flask, request, send_file, jsonify, send_from_directory, session, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = 'brothernoahbrothernoah' # Troque isso em produção

# Configurações
UPLOAD_FOLDER = 'storage'
DOLLY_FOLDER = 'dolly_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOLLY_FOLDER, exist_ok=True)

# Chave de criptografia para os arquivos .dolly (Deve ser fixa para poder ler arquivos antigos)
# Em produção, use variáveis de ambiente.
ENCRYPTION_KEY = b'gQjW8_5V4q3z2s1X0o9p8u7y6t5r4e3w2q1a0s9d8f7=' 
cipher_suite = Fernet(ENCRYPTION_KEY)

# --- CONFIGURAÇÃO DO TIDB ---
# Preencha com os dados do seu painel TiDB Cloud
DB_CONFIG = {
    'host': 'gateway01.us-west-2.prod.aws.tidbcloud.com', # Exemplo: troque pelo seu host
    'port': 4000,
    'user': '3jZGJoZm7yRDfbG.root', # Troque pelo seu usuário
    'password': 'zRbX8aXBISsk5Pft', # Troque pela sua senha
    'database': 'test'
}

def get_db_connection():
    """Conecta ao banco de dados TiDB."""
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"Erro de conexão com TiDB: {err}")
        return None

def init_db():
    """Cria a tabela de metadados no TiDB se não existir."""
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS arquivos_dolly (
                hash VARCHAR(64),
                filename VARCHAR(255),
                size_bytes BIGINT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                owner_id INT,
                PRIMARY KEY (hash)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                is_approved BOOLEAN DEFAULT FALSE,
                quota_used BIGINT DEFAULT 0
            )
        """)

        # Migração de Emergência: Adiciona a coluna owner_id se ela estiver faltando
        try:
            cursor.execute("ALTER TABLE arquivos_dolly ADD COLUMN owner_id INT")
        except mysql.connector.Error as err:
            # Ignora o erro 1060 (Duplicate column name) se a coluna já existir
            if err.errno != 1060:
                print(f"Aviso do Banco de Dados: {err}")

        conn.commit()
        cursor.close()
        conn.close()
        print("Banco de dados TiDB conectado e inicializado!")

def calculate_sha256(file_path):
    """Gera um hash único para o arquivo para garantir integridade."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

@app.route('/')
def index():
    return send_file('index.html')

# --- SISTEMA DE LOGIN E ADMIN ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password') # Em produção, use hash (bcrypt/argon2)
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            # Se for o usuário "admin", já cria como admin e aprovado
            is_admin = True if username.lower() == 'admin' else False
            is_approved = True if is_admin else False
            
            cursor.execute("INSERT INTO users (username, password, is_admin, is_approved) VALUES (%s, %s, %s, %s)", 
                           (username, password, is_admin, is_approved))
            conn.commit()
            return jsonify({"message": "Registrado com sucesso! Aguarde aprovação."})
        except mysql.connector.Error as err:
            return jsonify({"error": "Usuário já existe ou erro no banco."}), 400
        finally:
            conn.close()
    return jsonify({"error": "Erro de conexão"}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            session['is_approved'] = user['is_approved']
            session['quota_used'] = user['quota_used']
            return jsonify({"message": "Login realizado", "user": user})
        
    return jsonify({"error": "Credenciais inválidas"}), 401

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({"message": "Logout realizado"})

@app.route('/admin/pending_users', methods=['GET'])
def list_pending():
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, quota_used FROM users WHERE is_approved = FALSE")
    users = cursor.fetchall()
    conn.close()
    return jsonify(users)

@app.route('/admin/approve/<int:user_id>', methods=['POST'])
def approve_user(user_id):
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_approved = TRUE WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Usuário aprovado!"})

@app.route('/admin/users', methods=['GET'])
def list_all_users():
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, is_approved, quota_used FROM users")
    users = cursor.fetchall()
    conn.close()
    return jsonify(users)

@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Encontrar e deletar todos os arquivos desse usuário para liberar espaço
    cursor.execute("SELECT hash, filename FROM arquivos_dolly WHERE owner_id = %s", (user_id,))
    files = cursor.fetchall()
    
    for f in files:
        # Remove arquivos físicos
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, f['filename']))
            os.remove(os.path.join(DOLLY_FOLDER, f"{f['filename']}.dolly"))
        except OSError:
            pass # Arquivo já não existia
            
    # 2. Remove registros do banco
    cursor.execute("DELETE FROM arquivos_dolly WHERE owner_id = %s", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Usuário e seus arquivos deletados!"})

@app.route('/admin/files', methods=['GET'])
def list_all_files():
    if not session.get('is_admin'):
        return jsonify({"error": "Acesso negado"}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT hash, filename, size_bytes, owner_id FROM arquivos_dolly")
    files = cursor.fetchall()
    conn.close()
    return jsonify(files)

@app.route('/my_files', methods=['GET'])
def list_my_files():
    if 'user_id' not in session:
        return jsonify({"error": "Login necessário"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT hash, filename, size_bytes FROM arquivos_dolly WHERE owner_id = %s", (session['user_id'],))
    files = cursor.fetchall()
    conn.close()
    return jsonify(files)

@app.route('/delete_file/<file_hash>', methods=['DELETE'])
def delete_file(file_hash):
    if 'user_id' not in session:
        return jsonify({"error": "Login necessário"}), 401
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Pega info do arquivo para descontar cota e saber nome
    cursor.execute("SELECT filename, size_bytes, owner_id FROM arquivos_dolly WHERE hash = %s", (file_hash,))
    file_data = cursor.fetchone()
    
    if file_data:
        # --- VERIFICAÇÃO DE SEGURANÇA ---
        # Se não for o dono E não for admin, bloqueia a exclusão
        if file_data['owner_id'] != session['user_id'] and not session.get('is_admin'):
            conn.close()
            return jsonify({"error": "Você não pode deletar arquivos de outros usuários!"}), 403

        # Remove físicos
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, file_data['filename']))
            os.remove(os.path.join(DOLLY_FOLDER, f"{file_data['filename']}.dolly"))
        except OSError:
            pass
            
        # Atualiza cota do dono
        cursor.execute("UPDATE users SET quota_used = quota_used - %s WHERE id = %s", (file_data['size_bytes'], file_data['owner_id']))
        # Deleta registro
        cursor.execute("DELETE FROM arquivos_dolly WHERE hash = %s", (file_hash,))
        conn.commit()
        
    conn.close()
    return jsonify({"message": "Arquivo deletado!"})

@app.route('/criar_dolly', methods=['POST'])
def create_dolly():
    """
    1. Recebe o arquivo real.
    2. Salva no servidor.
    3. Cria o arquivo de metadados .dolly.
    4. Retorna o arquivo .dolly para o usuário.
    """
    # Verifica Login e Aprovação
    if 'user_id' not in session:
        return jsonify({"error": "Faça login para criar arquivos"}), 401
    
    if not session.get('is_approved'):
        return jsonify({"error": "Sua conta ainda não foi aprovada pelo Admin"}), 403

    if 'file' not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Nome de arquivo inválido"}), 400

    # Verifica Cota (500MB = 524288000 bytes)
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    if (session.get('quota_used', 0) + file_length) > 524288000:
        return jsonify({"error": "Cota de 500MB excedida!"}), 400
    file.seek(0) # Reseta ponteiro do arquivo

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    # Salva o arquivo original
    file.save(file_path)
    
    # Calcula metadados
    file_hash = calculate_sha256(file_path)
    file_size = os.path.getsize(file_path)

    # Salva o registro no TiDB
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        # INSERT IGNORE evita erro se o arquivo já foi cadastrado antes
        sql = "INSERT IGNORE INTO arquivos_dolly (hash, filename, size_bytes, owner_id) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (file_hash, filename, file_size, session['user_id']))
        
        # Atualiza cota no banco
        cursor.execute("UPDATE users SET quota_used = quota_used + %s WHERE id = %s", (file_size, session['user_id']))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Atualiza sessão local
        session['quota_used'] += file_size
    
    # Cria a estrutura do .dolly
    dolly_data = {
        "protocol": "dolly-v1",
        "original_name": filename,
        "size": file_size,
        "hash": file_hash,
        # Em um sistema P2P real, aqui iriam os IPs dos peers.
        # Neste exemplo centralizado, usamos a rota de download do nosso servidor.
        "download_endpoint": f"/baixar_conteudo/{filename}" 
    }
    
    # Salva o arquivo .dolly
    dolly_filename = f"{filename}.dolly"
    dolly_path = os.path.join(DOLLY_FOLDER, dolly_filename)
    
    # Criptografa o conteúdo do JSON
    json_str = json.dumps(dolly_data)
    encrypted_data = cipher_suite.encrypt(json_str.encode())
    
    with open(dolly_path, 'wb') as f:
        f.write(encrypted_data)
        
    return send_file(dolly_path, as_attachment=True)

@app.route('/ler_dolly', methods=['POST'])
def read_dolly():
    """
    Recebe um arquivo .dolly, lê onde está o arquivo real e inicia o download.
    """
    if 'dolly_file' not in request.files:
        return jsonify({"error": "Envie um arquivo .dolly"}), 400
        
    dolly_file = request.files['dolly_file']
    
    try:
        # Lê e Descriptografa
        encrypted_content = dolly_file.read()
        decrypted_content = cipher_suite.decrypt(encrypted_content)
        metadata = json.loads(decrypted_content.decode())
        
        if metadata.get("protocol") != "dolly-v1":
            return jsonify({"error": "Arquivo .dolly inválido ou versão antiga"}), 400
            
        # Redireciona para a rota de download real
        # Nota: Na prática, o frontend usaria essa URL para baixar
        return jsonify({
            "message": "Arquivo localizado!",
            "file_info": metadata,
            "download_url": metadata['download_endpoint']
        })
        
    except Exception as e:
        return jsonify({"error": f"Erro ao processar .dolly: {str(e)}"}), 500

@app.route('/baixar_conteudo/<filename>')
def download_content(filename):
    """Rota que entrega o arquivo real (binário)."""
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

# Garante que o banco inicia mesmo usando Gunicorn (Render)
init_db()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
