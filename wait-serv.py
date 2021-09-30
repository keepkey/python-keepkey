from waitress import serve
import kkbridge
serve(kkbridge.create_app(), host='127.0.0.1', port=1646)