from waitress import serve
import kkbridge
serve(kkbridge.create_app(), host='0.0.0.0', port=1646)