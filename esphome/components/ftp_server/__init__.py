import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import CONF_ID, CONF_PASSWORD, CONF_USERNAME, CONF_PORT

DEPENDENCIES = ['network']
CODEOWNERS = ['@votre_nom']

# Définir les constantes pour la configuration
CONF_ROOT_PATH = 'root_path'
CONF_ENABLE_TLS = 'enable_tls'
CONF_EXTERNAL_IP = 'external_ip'
CONF_PASSIVE_PORT_MIN = 'passive_port_min'
CONF_PASSIVE_PORT_MAX = 'passive_port_max'

# Créer l'espace de noms et la classe FTP
ftp_ns = cg.esphome_ns.namespace('ftp_server')
FTPServer = ftp_ns.class_('FTPServer', cg.Component)

# Schéma de configuration
CONFIG_SCHEMA = cv.Schema({
    cv.GenerateID(): cv.declare_id(FTPServer),
    cv.Required(CONF_USERNAME): cv.string,
    cv.Required(CONF_PASSWORD): cv.string,
    cv.Optional(CONF_ROOT_PATH, default='/'): cv.string,
    cv.Optional(CONF_PORT, default=21): cv.port,
    cv.Optional(CONF_ENABLE_TLS, default=False): cv.boolean,
    cv.Optional(CONF_EXTERNAL_IP): cv.string,
    cv.Optional(CONF_PASSIVE_PORT_MIN): cv.port,
    cv.Optional(CONF_PASSIVE_PORT_MAX): cv.port,
}).extend(cv.COMPONENT_SCHEMA)

async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    
    # Ajouter les paramètres à la classe C++
    cg.add(var.set_username(config[CONF_USERNAME]))
    cg.add(var.set_password(config[CONF_PASSWORD]))
    cg.add(var.set_root_path(config[CONF_ROOT_PATH]))
    cg.add(var.set_port(config[CONF_PORT]))
    
    # Ajouter les nouveaux paramètres TLS
    cg.add(var.set_enable_tls(config[CONF_ENABLE_TLS]))
    
    # Paramètres optionnels pour la connectivité externe
    if CONF_EXTERNAL_IP in config:
        cg.add(var.set_external_ip(config[CONF_EXTERNAL_IP]))
        
    if CONF_PASSIVE_PORT_MIN in config and CONF_PASSIVE_PORT_MAX in config:
        min_port = config[CONF_PASSIVE_PORT_MIN]
        max_port = config[CONF_PASSIVE_PORT_MAX]
        if min_port < max_port:
            cg.add(var.set_passive_port_range(min_port, max_port))
