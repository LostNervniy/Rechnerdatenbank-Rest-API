from flask import Flask, request, g
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_restx import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from Models import RevokedTokenModel
from Models.ComputerModel import ComputerModel
from Models.InstPcieModel import InstPcieModel
from Models.InstProcessorModel import InstProcessorModel
from Models.InstRamModel import InstRamModel
from Models.InstSoftwareModel import InstSoftwareModel
from Models.MainboardModel import MainboardModel
from Models.OSModel import OSModel
from Models.PcieModel import PcieModel
from Models.ProcessorModel import ProcessorModel
from Models.RamModel import RamModel
from Models.RoomModel import RoomModel
from Models.SoftwareModel import SoftwareModel
from Models.UserModel import UserModel

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
# app.config['SQLALCHEMY_ECHO'] = True


jwt = JWTManager(app)

api = Api(app)
CORS(app)
db = SQLAlchemy(app)

migrate = Migrate(app, db)


@app.teardown_appcontext
def shotdown_session(exception=None):
    db.session.remove()


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return RevokedTokenModel.is_jti_blacklisted(jti)


# USER
# /JWTAuth/user/create           POST
# /JWTAuth/user/all              GET
# /JWTAuth/user/id/<user_id>     GET, PUT, DELETE
@app.route('/JWTAuth/user/create', methods=['POST'])
def user_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_user = UserModel(email=data['email'], firstname=data['firstname'], lastname=data['lastname'],
                                 role=data['role'])
            db.session.add(new_user)
            db.session.commit()
            return {"message": f"user {new_user.firstname + ' ' + new_user.lastname} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/user/all', methods=['GET'])
def user_all():
    if request.method == 'GET':
        # users = UserModel.query.all()
        users = db.session.query(UserModel).all()
        db.session.commit()
        results = [
            {
                "user_id": user.user_id,
                "email": user.email,
                "firstname": user.firstname,
                "lastname": user.lastname,
                "role": user.role
            } for user in users
        ]
        return {"count": len(results), "users": results}


def return_user_by_id(user_id):
    # user = UserModel.query.get_or_404(user_id)
    user = db.session.query(UserModel).get_or_404(user_id)
    db.session.commit()

    response = {
        "user_id": user.user_id,
        "email": user.email,
        "firstname": user.firstname,
        "lastname": user.lastname,
        "role": user.role
    }
    return {"message": "success", "user": response}


@app.route('/JWTAuth/user/id/<user_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_user(user_id):
    # user = UserModel.query.get_or_404(user_id)
    user = db.session.query(UserModel).get_or_404(user_id)

    if request.method == 'GET':
        response = {
            "user_id": user.user_id,
            "email": user.email,
            "firstname": user.firstname,
            "lastname": user.lastname,
            "role": user.role
        }
        return {"message": "success", "user": response}

    elif request.method == 'PUT':
        data = request.get_json()
        user.email = data['email']
        user.firstname = data['firstname']
        user.lastname = data['lastname']
        user.role = data['role']
        current_db_session = db.session.object_session(user)
        current_db_session.add(user)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"user {user.firstname + ' ' + user.lastname} successfully updated."}

    elif request.method == 'DELETE':
        current_db_session = db.session.object_session(user)
        current_db_session.delete(user)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"User {user.firstname + ' ' + user.lastname} successfully deleted."}


# ROOM
# /JWTAuth/room/create          POST
# /JWTAuth/room/all             GET
# /JWTAuth/room/id/<room_id>    GET, PUT, DELETE
@app.route('/JWTAuth/room/create', methods=['POST'])
def room_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_room = RoomModel(description=data['description'], etage=data['etage'], name=data['name'])
            db.session.add(new_room)
            db.session.commit()
            return {"message": f"Room {new_room.name} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/room/all', methods=['GET'])
def room_all():
    if request.method == 'GET':
        # rooms = RoomModel.query.all()
        rooms = db.session.query(RoomModel).all()
        db.session.commit()
        results = [
            {
                "room_id": room.room_id,
                "description": room.description,
                "name": room.name,
                "etage": room.etage
            } for room in rooms
        ]

        return {"count": len(results), "room": results, "rooms": results}


def return_room_by_id(room_id):
    # room = RoomModel.query.get_or_404(room_id)
    room = db.session.query(RoomModel).get_or_404(room_id)
    db.session.commit()

    response = {
        "room_id": room.room_id,
        "description": room.description,
        "name": room.name,
        "etage": room.etage
    }
    return {"message": "success", "room": response}


@app.route('/JWTAuth/room/id/<room_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_room(room_id):
    # room = RoomModel.query.get_or_404(room_id)
    room = db.session.query(RoomModel).get(room_id)
    db.session.commit()
    if request.method == 'GET':
        response = {
            "room_id": room.room_id,
            "description": room.description,
            "name": room.name,
            "etage": room.etage
        }
        return {"message": "success", "room": response}

    elif request.method == 'PUT':
        data = request.get_json()
        room.name = data['name']
        room.etage = data['etage']
        room.description = data['description']
        current_db_session = db.session.object_session(room)
        current_db_session.add(room)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Room {room.name} successfully updated."}

    elif request.method == 'DELETE':
        current_db_session = db.session.object_session(room)
        current_db_session.delete(room)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Room {room.name} successfully deleted."}


# RAM
# /JWTAuth/ram/create                    POST               Create new ram
# /JWTAuth/ram/all                       GET                Get list of all ram
# /JWTAuth/ram/id/<ram_id>               GET, PUT, DELETE   Get, delete or change ram by id
# /JWTAuth/ram/standard/<ram_standard>   GET                Get ram by standard
# /JWTAuth/ram/pcid/<pcid>               GET                Get ram list by pcid
@app.route('/JWTAuth/ram/create', methods=['POST'])
def ram_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_ram = RamModel(name=data['name'], producer=data['producer'], standard=data['standard'],
                               frequency=data['frequency'], capacity=data['capacity'])
            db.session.add(new_ram)
            db.session.commit()
            return {"message": f"Ram {new_ram.name} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/ram/all', methods=['GET'])
def ram_all():
    if request.method == 'GET':
        # rams = RamModel.query.all()
        rams = db.session.query(RamModel).all()
        db.session.commit()
        results = [
            {
                'ram_id': ram.ram_id,
                'producer': ram.producer,
                'name': ram.name,
                'capacity': ram.capacity,
                'frequency': ram.frequency,
                'standard': ram.standard
            } for ram in rams
        ]

        return {"count": len(results), "ram": results}


@app.route('/JWTAuth/ram/id/<ram_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_ram(ram_id):
    # ram = RamModel.query.get_or_404(ram_id)
    ram = db.session.query(RamModel).get_or_404(ram_id)
    db.session.commit()
    if request.method == 'GET':
        response = {
            'ram_id': ram.ram_id,
            'producer': ram.producer,
            'name': ram.name,
            'capacity': ram.capacity,
            'frequency': ram.frequency,
            'standard': ram.standard
        }
        return {"message": "success", "ram": response}

    elif request.method == 'PUT':
        data = request.get_json()
        ram.producer = data['producer']
        ram.name = data['name']
        ram.capacity = data['capacity']
        ram.frequency = data['frequency']
        ram.standard = data['standard']
        current_db_session = db.session.object_session(ram)
        current_db_session.add(ram)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Ram {ram.name} successfully updated."}

    elif request.method == 'DELETE':
        current_db_session = db.session.object_session(ram)
        current_db_session.delete(ram)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Ram {ram.name} successfully deleted."}


@app.route('/JWTAuth/ram/standard/<ram_standard>', methods=['GET'])
def get_ram_by_standard(ram_standard):
    # rams = RamModel.query.filter(RamModel.standard == ram_standard)
    rams = db.session.query(RamModel).filter(RamModel.standard == ram_standard)
    db.session.commit()
    if request.method == 'GET':
        results = [{
            'ram_id': ram.ram_id,
            'producer': ram.producer,
            'name': ram.name,
            'capacity': ram.capacity,
            'frequency': ram.frequency,
            'standard': ram.standard
        } for ram in rams
        ]

        return {"count": len(results), "ram": results, "rams": results}


@app.route('/JWTAuth/ram/pcid/<pcid>', methods=['GET'])
def get_installed_ram_by_pcid(pcid):
    # ram_list_all = InstRamModel.query.all()
    ram_list_all = db.session.query(InstRamModel).all()
    db.session.commit()
    correct_ram_list = []
    for ram_list in ram_list_all:
        if ram_list.computer_id == pcid:
            correct_ram_list.append(ram_list)

    results = []
    for ram_id in correct_ram_list:
        # rams = RamModel.query.filter(RamModel.ram_id == ram_id.ram_id)
        rams = db.session.query(RamModel).filter(RamModel.ram_id == ram_id.ram_id)
        db.session.commit()
        for ram in rams:
            results.append({
                'ram_id': ram.ram_id,
                'producer': ram.producer,
                'name': ram.name,
                'capacity': ram.capacity,
                'frequency': ram.frequency,
                'standard': ram.standard
            })

    return {"count": len(results), "rams": results}


def return_ram_by_id(id):
    # ram_list_all = InstRamModel.query.all()
    ram_list_all = db.session.query(InstRamModel).all()
    db.session.commit()
    correct_ram_list = []
    for ram_list in ram_list_all:
        if ram_list.computer_id == id:
            correct_ram_list.append(ram_list)

    results = []
    for ram_id in correct_ram_list:
        # rams = RamModel.query.filter(RamModel.ram_id == ram_id.ram_id)
        rams = db.session.query(RamModel).filter(RamModel.ram_id == ram_id.ram_id)
        db.session.commit()
        for ram in rams:
            results.append({
                'ram_id': ram.ram_id,
                'producer': ram.producer,
                'name': ram.name,
                'capacity': ram.capacity,
                'frequency': ram.frequency,
                'standard': ram.standard
            })

    return {"message": "success", "rams": results}


# PCIE
# /JWTAuth/pcie/create                      POST                Create pcie
# /JWTAuth/pcie/all                         GET                 Get a list of all PCIEs
# /JWTAuth/pcie/id/<pcie_id>                GET, PUT, DELETE    Get, Edit, or delete a pcie by pcie_id
# /JWTAuth/pcie/pcid/<pcid>                 GET                 Get pcie list by pcid
@app.route('/JWTAuth/pcie/create', methods=['POST'])
def pcie_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_pcie = PcieModel(name=data['name'], producer=data['producer'], type=data['type'])
            db.session.add(new_pcie)
            db.session.commit()
            return {"message": f"Ram {new_pcie.name} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/pcie/all', methods=['GET'])
def pcie_all():
    if request.method == 'GET':
        # pcies = PcieModel.query.all()
        pcies = db.session.query(PcieModel).all()
        db.session.commit()
        results = [
            {
                'pcie_id': pcie.pcie_id,
                'producer': pcie.producer,
                'name': pcie.name,
                'type': pcie.type
            } for pcie in pcies
        ]

        return {"count": len(results), "pcie": results}


@app.route('/JWTAuth/pcie/id/<pcie_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_pcie(pcie_id):
    # pcie = PcieModel.query.get_or_404(pcie_id)
    pcie = db.session.query(PcieModel).get_or_404(pcie_id)
    db.session.commit()
    if request.method == 'GET':
        response = {
            'pcie_id': pcie.ram_id,
            'producer': pcie.producer,
            'name': pcie.name,
            'type': pcie.type
        }
        return {"message": "success", "pcie": response}

    elif request.method == 'PUT':
        data = request.get_json()
        pcie.producer = data['producer']
        pcie.name = data['name']
        pcie.type = data['type']
        current_db_session = g.db.session.object_session(pcie)
        current_db_session.add(pcie)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Pcie {pcie.name} successfully updated."}

    elif request.method == 'DELETE':
        current_db_session = db.session.object_session(pcie)
        current_db_session.delete(pcie)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Pcie {pcie.name} successfully deleted."}


@app.route('/JWTAuth/pcie/pcid/<pcid>', methods=['GET'])
def get_installed_pcie_by_pcid(pcid):
    # pcies = InstPcieModel.query.filter(InstPcieModel.computer_id == pcid)
    pcies = db.session.query(InstPcieModel).filter(InstPcieModel.computer_id == pcid)
    db.session.commit()
    pcie_id_list = [
        {
            'pcie_id': pcie.pcie_id
        } for pcie in pcies
    ]

    pcie_list = []

    for pcie_id in pcie_id_list:
        # pcie = PcieModel.query.get_or_404(pcie_id)
        pcie = db.session.query(PcieModel).get_or_404(pcie_id)
        db.session.commit()
        pcie_list.append({
            'pcie_id': pcie.pcie_id,
            'producer': pcie.producer,
            'name': pcie.name,
            'type': pcie.type
        })

    return {"count": len(pcie_list), "pcies": pcie_list}


def return_pcie_by_id(id):
    # installed_pcie = InstPcieModel.query.filter(InstPcieModel.computer_id == id)
    installed_pcie = db.session.query(InstPcieModel).filter(InstPcieModel.computer_id == id)
    db.session.commit()
    pcie_list = []
    for pcie in installed_pcie:
        # pcie_items = PcieModel.query.filter(PcieModel.pcie_id == pcie.pcie_id)
        pcie_items = db.session.query(PcieModel).filter(PcieModel.pcie_id == pcie.pcie_id)
        db.session.commit()
        for pcie_item in pcie_items:
            pcie_list.append({
                'pcie_id': pcie_item.pcie_id,
                'producer': pcie_item.producer,
                'name': pcie_item.name,
                'type': pcie_item.type
            })

    return {"message": "success", "pcie": pcie_list}


# PROCESSOR
# /JWTAuth/processor/create                      POST                   Create processor
# /JWTAuth/processor/all                         GET                    Get a list of all processor
# /JWTAuth/processor/id/<processor_id>           GET, PUT, DELETE       Get, Edit, or delete a processor by processor_id
# /JWTAuth/processor/pcid/<pcid>                 GET                    Get processor list by pcid
# /JWTAuth/processor/socket/<socket>
@app.route('/JWTAuth/processor/create', methods=['POST'])
def processor_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_processor = ProcessorModel(name=data['name'], producer=data['producer'], clock=data['clock'],
                                           architecture=data['architecture'], socket=data['socket'])
            db.session.add(new_processor)
            db.session.commit()
            return {"message": f"Processor {new_processor.name} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/processor/all', methods=['GET'])
def processor_all():
    if request.method == 'GET':
        # processors = ProcessorModel.query.all()
        processors = db.session.query(ProcessorModel).all()
        db.session.commit()
        results = [
            {
                'processor_id': processor.processor_id,
                'producer': processor.producer,
                'name': processor.name,
                'clock': processor.clock,
                'architecture': processor.architecture,
                'socket': processor.socket
            } for processor in processors
        ]

        return {"count": len(results), "processors": results, "processor": results}


@app.route('/JWTAuth/processor/id/<processor_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_processor(processor_id):
    # processor = ProcessorModel.query.get_or_404(processor_id)
    processor = db.session.query(ProcessorModel).get_or_404(processor_id)
    db.session.commit()
    if request.method == 'GET':
        response = {
            'processor_id': processor.processor_id,
            'producer': processor.producer,
            'name': processor.name,
            'clock': processor.clock,
            'architecture': processor.architecture,
            'socket': processor.socket
        }
        return {"message": "success", "processors": response, "processor": response}

    elif request.method == 'PUT':
        data = request.get_json()
        processor.producer = data['producer']
        processor.name = data['name']
        processor.clock = data['clock']
        processor.architecture = data['architecture']
        processor.socket = data['socket']
        current_db_session = db.session.object_session(processor)
        current_db_session.add(processor)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Processor {processor.name} successfully updated."}

    elif request.method == 'DELETE':
        current_db_session = db.session.object_session(processor)
        current_db_session.delete(processor)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Processor {processor.name} successfully deleted."}


@app.route('/JWTAuth/processor/socket/<socket>', methods=['GET'])
def get_processor_by_socket_id(socket):
    # processors = ProcessorModel.query.all()
    processors = db.session.query(ProcessorModel).all()
    db.session.commit()
    results = []
    for processor in processors:
        if processor.socket == socket:
            results.append(
                {
                    'processor_id': processor.processor_id,
                    'producer': processor.producer,
                    'name': processor.name,
                    'clock': processor.clock,
                    'architecture': processor.architecture,
                    'socket': processor.socket
                }
            )

    return {"count": len(results), "processors": results, "processor": results}


@app.route('/JWTAuth/processor/pcid/<pcid>', methods=['GET'])
def get_installed_processor_by_pcid(pcid):
    # processors = InstProcessorModel.query.filter(InstProcessorModel.computer_id == pcid)
    processors = db.session.query(InstProcessorModel).filter(InstProcessorModel.computer_id == pcid)
    db.session.commit()
    processor_id_list = [
        {
            'processor_id': processor.processor_id
        } for processor in processors
    ]

    processor_list = []

    for processor_id in processor_id_list:
        # processor = ProcessorModel.query.get_or_404(processor_id)
        processor = db.session.query(ProcessorModel).get_or_404(processor_id)
        db.session.commit()
        processor_list.append({
            'processor_id': processor.processor_id,
            'producer': processor.producer,
            'name': processor.name,
            'clock': processor.clock,
            'architecture': processor.architecture,
            'socket': processor.socket
        })

    return {"count": len(processor_list), "processors": processor_list}


def return_processor_by_id(id):
    # processor_id_list = InstProcessorModel.query.filter(InstProcessorModel.computer_id == id)
    processor_id_list = db.session.query(InstProcessorModel).filter(InstProcessorModel.computer_id == id)
    db.session.commit()
    processor_list = []

    for processor_id in processor_id_list:
        # processor = ProcessorModel.query.get_or_404(processor_id.processor_id)
        processor = db.session.query(ProcessorModel).get_or_404(processor_id.processor_id)
        db.session.commit()
        processor_list.append({
            'processor_id': processor.processor_id,
            'producer': processor.producer,
            'name': processor.name,
            'clock': processor.clock,
            'architecture': processor.architecture,
            'socket': processor.socket
        })

        return {"count": len(processor_list), "processors": processor_list}


# MAINBOARD
# /JWTAuth/mainboard/create
# /JWTAuth/mainboard/all
# /JWTAuth/mainbiard/id/<mainboard_id>
# /JWTAuth/mainboard/pcid/<pcid>
@app.route('/JWTAuth/mainboard/create', methods=['POST'])
def mainboard_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_mainboard = MainboardModel(producer=data['producer'], name=data['name'], socket=data['socket'],
                                           sockets=data['sockets'],
                                           chipset=data['chipset'], dimmslots=data['dimmslots'],
                                           pcieslots=data['pcieslots'], m2slots=data['m2slots'],
                                           sataconnectors=data['sataconnectors'], formfactor=data['formfactor'],
                                           ddr=data['ddr'])
            db.session.add(new_mainboard)
            db.session.commit()
            return {"message": f"Mainboard {new_mainboard.name} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/mainboard/all', methods=['GET'])
def mainboard_all():
    if request.method == 'GET':
        # mainboards = MainboardModel.query.all()
        mainboards = db.session.query(MainboardModel).all()
        db.session.commit()
        results = [
            {
                'mainboard_id': mainboard.mainboard_id,
                'producer': mainboard.producer,
                'name': mainboard.name,
                'socket': mainboard.socket,
                'sockets': mainboard.sockets,
                'chipset': mainboard.chipset,
                'dimmslots': mainboard.dimmslots,
                'pcieslots': mainboard.pcieslots,
                'm2slots': mainboard.m2slots,
                'sataconnectors': mainboard.sataconnectors,
                'formfactor': mainboard.formfactor,
                'ddr': mainboard.ddr,
            } for mainboard in mainboards
        ]

        return {"count": len(results), "mainboard": results}


@app.route('/JWTAuth/mainboard/id/<mainboard_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_mainboard(mainboard_id):
    # mainboard = MainboardModel.query.get_or_404(mainboard_id)
    mainboard = db.session.query(MainboardModel).get_or_404(mainboard_id)
    db.session.commit()
    if request.method == 'GET':
        response = {
            'mainboard_id': mainboard.mainboard_id,
            'producer': mainboard.producer,
            'name': mainboard.name,
            'socket': mainboard.socket,
            'sockets': mainboard.sockets,
            'chipset': mainboard.chipset,
            'dimmslots': mainboard.dimmslots,
            'pcieslots': mainboard.pcieslots,
            'm2slots': mainboard.m2slots,
            'sataconnectors': mainboard.sataconnectors,
            'formfactor': mainboard.formfactor,
            'ddr': mainboard.ddr,
        }
        return {"message": "success", "mainboard": response}

    elif request.method == 'PUT':
        data = request.get_json()
        mainboard.producer = data['producer']
        mainboard.name = data['name']
        mainboard.socket = data['socket']
        mainboard.sockets = data['sockets']
        mainboard.chipset = data['chipset']
        mainboard.dimmslots = data['dimmslots']
        mainboard.pcieslots = data['pcieslots']
        mainboard.m2slots = data['m2slots']
        mainboard.sataconnectors = data['sataconnectors']
        mainboard.formfactor = data['formfactor']
        mainboard.ddr = data['ddr']
        current_db_session = db.session.object_session(mainboard)
        current_db_session.add(mainboard)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Mainboard {mainboard.name} successfully updated."}

    elif request.method == 'DELETE':
        current_db_session = db.session.object_session(mainboard)
        current_db_session.delete(mainboard)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Mainboard {mainboard.name} successfully deleted."}


@app.route('/JWTAuth/mainboard/pcid/<pcid>', methods=['GET'])
def get_installed_mainboard_by_pcid(pcid):
    # computers = ComputerModel.query.filter(ComputerModel.computer_id == pcid)
    computers = db.session.query(ComputerModel).filter(ComputerModel.computer_id == pcid)
    db.session.commit()
    mainboards = None
    for computer in computers:
        mainboards = db.session.query(MainboardModel).filter(MainboardModel.mainboard_id == computer.mainboard_id)
        db.session.commit()
        # mainboards = MainboardModel.query.filter(MainboardModel.mainboard_id == computer.mainboard_id)

    response = None
    for mainboard in mainboards:
        response = {
            'mainboard_id': mainboard.mainboard_id,
            'producer': mainboard.producer,
            'name': mainboard.name,
            'socket': mainboard.socket,
            'sockets': mainboard.sockets,
            'chipset': mainboard.chipset,
            'dimmslots': mainboard.dimmslots,
            'pcieslots': mainboard.pcieslots,
            'm2slots': mainboard.m2slots,
            'sataconnectors': mainboard.sataconnectors,
            'formfactor': mainboard.formfactor,
            'ddr': mainboard.ddr
        }

    return {"message": "success", "mainboard": response}


def return_mainboard_by_id(id):
    # mainboards = MainboardModel.query.filter(MainboardModel.mainboard_id == id)
    mainboards = db.session.query(MainboardModel).filter(MainboardModel.mainboard_id == id)
    db.session.commit()
    result = []
    for mainboard in mainboards:
        result.append({
            'mainboard_id': mainboard.mainboard_id,
            'producer': mainboard.producer,
            'name': mainboard.name,
            'socket': mainboard.socket,
            'sockets': mainboard.sockets,
            'chipset': mainboard.chipset,
            'dimmslots': mainboard.dimmslots,
            'pcieslots': mainboard.pcieslots,
            'm2slots': mainboard.m2slots,
            'sataconnectors': mainboard.sataconnectors,
            'formfactor': mainboard.formfactor,
            'ddr': mainboard.ddr
        })
    return {"message": "success", "mainboard": result}


# COMPUTER
# /JWTAuth/computer/create
# /JWTAuth/computer/all
# /JWTAuth/computer/edv/<edv>
# /JWTAuth/computer/userid/<userid>
# /JWTAuth/computer/roomid/<roomid>
# /JWTAuth/computer/mainboardid/<mainboardid>
# /JWTAuth/computer/id/<computer_id>
# /JWTAuth/computer/all/detailed
# /JWTAuth/computer/minimal/<id>
# TODO
# /JWTAuth/computer/processor
# /JWTAuth/computer/ram
# /JWTAuth/computer/pcie
@app.route('/JWTAuth/computer/create', methods=['POST'])
def computer_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_computer = ComputerModel(name=data['name'], edv=['edv'], room_id=data['room_id'],
                                         user_id=data['user_id'], ip=data['ip'], os_id=data['os_id'], type=data['type'],
                                         mainboard_id=data['mainboard_id'], note=data['note'],
                                         borrowable=data['borrowable'], storage=data['storage'])
            db.session.add(new_computer)
            db.session.commit()
            return {"message": f"Computer {new_computer.name} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/computer/processor', methods=['POST'])
def computer_combine_processor():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            combine_processor = InstProcessorModel(processor_id=data['processor_id'], computer_id=data['computer_id'])
        db.session.add(combine_processor)
        db.session.commit()
        return {"message": f"Success"}
    else:
        return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/computer/processor/deinstall/<pc_id>', methods=['DELETE'])
def computer_delete_processor(pc_id):
    if request.method == 'DELETE':
        inst_processor = db.session.query(InstProcessorModel).filter(InstProcessorModel.computer_id == pc_id)
        for proc in inst_processor:
            db.session.delete(proc)
        db.session.commit()
        return "Yes"


@app.route('/JWTAuth/computer/ram', methods=['POST'])
def computer_combine_ram():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            print(data)
            combine_ram = InstRamModel(ram_id=data['ram_id'], computer_id=data['computer_id'])
        db.session.add(combine_ram)
        db.session.commit()
        return {"message": f"Success"}
    else:
        return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/computer/ram/deinstall/<pc_id>', methods=['DELETE'])
def computer_delete_ram(pc_id):
    if request.method == 'DELETE':
        inst_ram = db.session.query(InstRamModel).filter(InstRamModel.computer_id == pc_id)
        for ram in inst_ram:
            db.session.delete(ram)
        db.session.commit()
        return "Yes"


@app.route('/JWTAuth/computer/pcie', methods=['POST'])
def computer_combine_pcie():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            combine_pcie = InstPcieModel(pcie_id=data['pcie_id'], computer_id=data['computer_id'])
        db.session.add(combine_pcie)
        db.session.commit()
        return {"message": f"Success"}
    else:
        return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/computer/pcie/deinstall/<pc_id>', methods=['DELETE'])
def computer_delete_pcie(pc_id):
    if request.method == 'DELETE':
        inst_pcie = db.session.query(InstPcieModel).filter(InstPcieModel.computer_id == pc_id)
        for pcie in inst_pcie:
            db.session.delete(pcie)
        db.session.commit()
        return "Yes"


@app.route('/JWTAuth/computer/all', methods=['GET'])
def computer_all():
    if request.method == 'GET':
        # computers = ComputerModel.query.all()
        computers = db.session.query(ComputerModel).all()
        db.session.commit()

        results = [
            {
                'computer_id': computer.computer_id,
                'name': computer.name,
                'edv': computer.edv,
                'room_id': computer.room_id,
                'user_id': computer.user_id,
                'ip': computer.ip,
                'os_id': computer.os_id,
                'type': computer.type,
                'mainboard_id': computer.mainboard_id,
                'note': computer.note,
                'borrowable': computer.borrowable,
                'storage': computer.storage
            } for computer in computers
        ]
        return {"count": len(results), "computer": results}


@app.route('/JWTAuth/computer/edv/<edv>', methods=['GET'])
def computer_by_edv(edv):
    # computers = ComputerModel.query.filter(ComputerModel.edv == edv)
    computers = db.session.query(ComputerModel).filter(ComputerModel.edv == edv)
    db.session.commit()
    results = []
    for computer in computers:
        results.append({
            'computer_id': computer.computer_id,
            'name': computer.name,
            'edv': computer.edv,
            'room_id': computer.room_id,
            'user_id': computer.user_id,
            'ip': computer.ip,
            'os_id': computer.os_id,
            'type': computer.type,
            'mainboard_id': computer.mainboard_id,
            'note': computer.note,
            'borrowable': computer.borrowable,
            'storage': computer.storage
        })
    return {"count": len(results), "computers": results}


@app.route('/JWTAuth/computer/detailed', methods=['GET'])
def computer_all_detailed():
    # computers = ComputerModel.query.all()
    computers = db.session.query(ComputerModel).all()
    db.session.commit()
    results = []
    for computer in computers:
        results.append({
            'computer_id': computer.computer_id,
            'name': computer.name,
            'edv': computer.edv,
            'room': return_room_by_id(computer.room_id),
            'user': return_user_by_id(computer.user_id),
            'ip': computer.ip,
            'os': return_os_by_id(computer.os_id),
            'type': computer.type,
            'mainboard': return_mainboard_by_id(computer.mainboard_id),
            'note': computer.note,
            'borrowable': computer.borrowable,
            'storage': computer.storage,
            'pcie': return_pcie_by_id(computer.computer_id),
            'ram': return_ram_by_id(computer.computer_id),
            'software': return_software_by_id(computer.computer_id),
            'processor': return_processor_by_id(computer.computer_id)
        })

    return {"count": len(results), "computers": results}


@app.route('/JWTAuth/computer/minimal/<id>')
def return_by_computer_id(id):
    # computer = ComputerModel.query.get_or_404(id)
    computer = db.session.query(ComputerModel).get_or_404(id)
    db.session.commit()
    result = {
        'computer_id': computer.computer_id,
        'name': computer.name,
        'edv': computer.edv,
        'ip': computer.ip,
        'software': InstSoftwareModel.return_computer_by_id(computer.computer_id)
    }
    return {"computer": result}


@app.route('/JWTAuth/computer/edv/<edv>', methods=['GET'])
def return_id_for_edv(edv):
    # computer = ComputerModel.query.get_or_404(edv)
    computer = db.session.query(ComputerModel).get_or_404(edv)
    db.session.commit()

    response = {
        'computer_id': computer.computer_id
    }
    return {"message": "success", "computer": response}


@app.route('/JWTAuth/computer/userid/<userid>', methods=['GET'])
def return_by_user_id(userid):
    # computers = ComputerModel.query.filter(ComputerModel.user_id == userid)
    computers = db.session.query(ComputerModel).filter(ComputerModel.user_id == userid)
    db.session.commit()
    results = [
        {
            'computer_id': computer.computer_id,
            'name': computer.name,
            'edv': computer.edv,
            'room_id': computer.room_id,
            'user_id': computer.user_id,
            'ip': computer.ip,
            'os_id': computer.os_id,
            'type': computer.type,
            'mainboard_id': computer.mainboard_id,
            'note': computer.note,
            'borrowable': computer.borrowable,
            'storage': computer.storage
        } for computer in computers
    ]
    return {"count": len(results), "computers": results}


@app.route('/JWTAuth/computer/roomid/<roomid>', methods=['GET'])
def return_by_room_id(roomid):
    # computers = ComputerModel.query.filter(ComputerModel.room_id == roomid)
    computers = db.session.query(ComputerModel).filter(ComputerModel.room_id == roomid)
    db.session.commit()
    results = [
        {
            'computer_id': computer.computer_id,
            'name': computer.name,
            'edv': computer.edv,
            'room_id': computer.room_id,
            'user_id': computer.user_id,
            'ip': computer.ip,
            'os_id': computer.os_id,
            'type': computer.type,
            'mainboard_id': computer.mainboard_id,
            'note': computer.note,
            'borrowable': computer.borrowable,
            'storage': computer.storage
        } for computer in computers
    ]
    return {"count": len(results), "computers": results}


@app.route('/JWTAuth/computer/mainboardid/<mainboardid>', methods=['GET'])
def return_by_mainboard_id(mainboardid):
    # computers = ComputerModel.query.filter(ComputerModel.mainboard_id == mainboardid)
    computers = db.session.query(ComputerModel).filter(ComputerModel.mainboard_id == mainboardid)
    db.session.commit()
    results = [
        {
            'computer_id': computer.computer_id,
            'name': computer.name,
            'edv': computer.edv,
            'room_id': computer.room_id,
            'user_id': computer.user_id,
            'ip': computer.ip,
            'os_id': computer.os_id,
            'type': computer.type,
            'mainboard_id': computer.mainboard_id,
            'note': computer.note,
            'borrowable': computer.borrowable,
            'storage': computer.storage
        } for computer in computers
    ]
    return {"count": len(results), "computers": results}


@app.route('/JWTAuth/computer/edit/<computer_id>', methods=['PUT'])
def edit_computer(computer_id):
    computers = db.session.query(ComputerModel).filter(ComputerModel.computer_id == computer_id)
    for computer in computers:
        if request.method == 'PUT':
            data = request.get_json()
            computer.name = data['name']
            computer.edv = data['edv']
            computer.room_id = data['room_id']
            computer.user_id = data['user_id']
            computer.ip = data['ip']
            computer.os_id = data['os_id']
            computer.type = data['type']
            computer.mainboard_id = data['mainboard_id']
            computer.note = data['note']
            computer.borrowable = data['borrowable']
            computer.storage = data['storage']
            current_db_session = db.session.object_session(computer)
            current_db_session.add(computer)
            current_db_session.commit()
            db.session.commit()
    return {"message": f"Computer {computer.name} successfully updated."}


@app.route('/JWTAuth/computer/id/<computer_id>', methods=['GET', 'DELETE'])
def handle_computer(computer_id):
    # computer = ComputerModel.query.get_or_404(computer_id)
    computer = db.session.query(ComputerModel).get_or_404(computer_id)

    if request.method == 'GET':
        response = {
            'computer_id': computer.computer_id,
            'name': computer.name,
            'edv': computer.edv,
            'room_id': computer.room_id,
            'user_id': computer.user_id,
            'ip': computer.ip,
            'os_id': computer.os_id,
            'type': computer.type,
            'mainboard_id': computer.mainboard_id,
            'note': computer.note,
            'borrowable': computer.borrowable,
            'storage': computer.storage
        }
        db.session.commit()
        return {"message": "success", "computer": response}


    elif request.method == 'DELETE':
        current_db_session = db.session.object_session(computer)
        current_db_session.delete(computer)
        current_db_session.commit()
        current_db_session.close()
        db.session.close()
        return {"message": f"Computer {computer.name} successfully deleted."}


# Betriebssystem
# /JWTAuth/os/create
# /JWTAuth/os/all
# /JWTAuth/os/id/<os_id>
@app.route('/JWTAuth/os/create', methods=['POST'])
def os_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_os = OSModel(name=data['name'], version=data['version'])
            db.session.add(new_os)
            db.session.commit()
            return {"message": f"OS {new_os.name} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/os/all', methods=['GET'])
def os_all():
    if request.method == 'GET':
        # oss = OSModel.query.all()
        oss = db.session.query(OSModel).all()
        db.session.commit()

        results = [
            {
                'os_id': os.os_id,
                'name': os.name,
                'version': os.version
            } for os in oss
        ]

        return {"count": len(results), "os": results}


@app.route('/JWTAuth/os/id/<os_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_os(os_id):
    # oss = OSModel.query.filter(OSModel.os_id == os_id)
    oss = db.session.query(OSModel).filter(OSModel.os_id == os_id)
    db.session.commit()
    if request.method == 'GET':
        response = None
        for os in oss:
            response = {
                'os_id': os.os_id,
                'name': os.name,
                'version': os.version
            }
        return {"message": "success", "os": response}

    elif request.method == 'PUT':
        for os in oss:
            data = request.get_json()
            os.name = data['name']
            os.version = data['version']
            current_db_session = db.session.object_session(os)
            current_db_session.add(os)
            current_db_session.commit()
            db.session.commit()
        return {"message": f"OS {os.name} successfully updated."}

    elif request.method == 'DELETE':
        for os in oss:
            current_db_session = db.session.object_session(os)
            current_db_session.delete(os)
            current_db_session.commit()
            db.session.commit()
        return {"message": f"OS {os.name} successfully deleted."}


def return_os_by_id(id):
    # oss = OSModel.query.filter(OSModel.os_id == id)
    oss = db.session.query(OSModel).filter(OSModel.os_id == id)
    db.session.commit()
    result = []
    for os in oss:
        result.append({
            'os_id': os.os_id,
            'name': os.name,
            'version': os.version
        })

    return {"message": "success", "os": result}


# SOFTWARE
# /JWTAuth/software/create
# /JWTAuth/software/id/<software_id>
# /JWTAuth/software/all
# /JWTAuth/software/connect
@app.route('/JWTAuth/software/create', methods=['POST'])
def software_create():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_software = SoftwareModel(name=data['name'], description=data['description'])
            db.session.add(new_software)
            db.session.commit()
            return {"message": f"Software {new_software.name} has been created successfully."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/software/id/<software_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_software(software_id):
    # software = SoftwareModel.query.get_or_404(software_id)
    software = db.session.query(SoftwareModel).get_or_404(software_id)
    db.session.commit()

    if request.method == 'GET':
        response = {
            'software_id': software.software_id,
            'name': software.name,
            'description': software.description
        }
        return {"message": "success", "software": response}

    elif request.method == 'PUT':
        data = request.get_json()
        software.name = data['name']
        software.version = data['description']
        current_db_session = db.session.object_session(software)
        current_db_session.add(software)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Software {software.name} successfully updated."}

    elif request.method == 'DELETE':
        current_db_session = db.session.object_session(software)
        current_db_session.delete(software)
        current_db_session.commit()
        db.session.commit()
        return {"message": f"Software {software.name} successfully deleted."}


@app.route('/JWTAuth/software/all', methods=['GET'])
def software_all():
    if request.method == 'GET':
        # softwares = SoftwareModel.query.all()
        softwares = db.session.query(SoftwareModel).all()
        db.session.commit()

        results = [
            {
                'software_id': software.software_id,
                'name': software.name,
                'description': software.description
            } for software in softwares
        ]

        return {"count": len(results), "software": results}


def return_software_by_id(id):
    # software_id_list = InstSoftwareModel.query.all()
    software_id_list = db.session.query(InstSoftwareModel).all()
    db.session.commit()
    correct_software_list = []
    for software_id_item in software_id_list:
        if software_id_item.computer_id == id:
            correct_software_list.append(software_id_item)

    results = []
    for software_id in correct_software_list:
        # softwares = SoftwareModel.query.filter(SoftwareModel.software_id == software_id.software_id)
        softwares = db.session.query(SoftwareModel).filter(SoftwareModel.software_id == software_id.software_id)
        db.session.commit()
        for software in softwares:
            results.append({
                "software_id": software.software_id,
                "name": software.name,
                "description": software.description
            })

    return {"message": "success", "software": results}


@app.route('/JWTAuth/software/connect', methods=['POST'])
def connect_software_and_pc():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            connected_PCSoftware = InstSoftwareModel(software_id=data['software_id'], computer_id=data['computer_id'])
            db.session.add(connected_PCSoftware)
            db.session.commit()
            return {
                "message": f"Software {connected_PCSoftware.software_id} and computer {connected_PCSoftware.computer_id} connected."}
        else:
            return {"error": "The request payload is not in JSON format"}


@app.route('/JWTAuth/software/disconnect/<pc_id>/<software_id>', methods=['DELETE'])
def disconnect_software_and_pc(pc_id, software_id):
    if request.method == 'DELETE':
        # toDelete = InstSoftwareModel.query.filter(InstSoftwareModel.computer_id == pc_id).filter(InstSoftwareModel.software_id == software_id)
        toDelete = db.session.query(InstSoftwareModel).filter(InstSoftwareModel.computer_id == pc_id).filter(
            InstSoftwareModel.software_id == software_id)
        db.session.commit()
        for item in toDelete:
            current_db_session = db.session.object_session(item)
            current_db_session.delete(item)
            current_db_session.commit()
            db.session.commit()
            return {"message": f"Software {software_id} and computer {pc_id} disconnected."}


# INSTALLED
# /JWTAuth/installed/ram/all            GET
# /JWTAuth/installed/ram/pcid/<pc_id>   GET, DELETE
# /JWTAuth/installed/pcie/all
# /JWTAuth/installed/pcie/pcid/<pc_id>  GET, DELETE
@app.route('/JWTAuth/installed/ram/all', methods=['GET'])
def installed_ram_all():
    if request.method == 'GET':
        # installed_rams = InstRamModel.query.all()
        installed_rams = db.session.query(InstRamModel).all()
        db.session.commit()
        results = [
            {
                'ram_id': installed_ram.ram_id,
                'computer_id': installed_ram.computer_id,
                'r_installed_id': installed_ram.r_installed_id
            } for installed_ram in installed_rams
        ]

        return {"count": len(results), "installed_rams": results}


@app.route('/JWTAuth/installed/pcie/all', methods=['GET'])
def installed_pcie_all():
    if request.method == 'GET':
        # installed_pcies = InstPcieModel.query.all()
        installed_pcies = db.session.query(InstPcieModel).all()
        db.session.commit()
        results = [
            {
                'pcie_id': installed_pcie.ram_id,
                'computer_id': installed_pcie.computer_id,
                'p_installed_id': installed_pcie.r_installed_id
            } for installed_pcie in installed_pcies
        ]

        return {"count": len(results), "installed_pcies": results}


@app.route('/JWTAuth/installed/software/all', methods=['GET'])
def installed_software_all():
    if request.method == 'GET':
        # installed_softwares = InstSoftwareModel.query.all()
        installed_softwares = db.session.query(InstSoftwareModel).all()
        db.session.commit()
        results = [
            {
                'software_id': installed_software.software_id,
                'computer_id': installed_software.computer_id,
                's_installed_id': installed_software.s_installed_id,
            } for installed_software in installed_softwares
        ]

        return {"count": len(results), "installed_software": results}


@app.route('/JWTAuth/installed/software/<pc_id>', methods=['GET'])
def get_all_pcs_with_software(pc_id):
    if request.method == 'GET':
        # installed_softwares = InstSoftwareModel.query.filter(InstSoftwareModel.computer_id == pc_id)
        installed_softwares = db.session.query(InstSoftwareModel).filter(InstSoftwareModel.computer_id == pc_id)
        db.session.commit()
        results = [
            {
                'software_id': installed_software.software_id,
                'computer_id': installed_software.computer_id,
                's_installed_id': installed_software.s_installed_id,
            } for installed_software in installed_softwares
        ]

        return {"count": len(results), "installed_software": results}


@app.route('/JWTAuth/installed/software/<software_id>', methods=['DELETE'])
def delete_all_connected_software_info(software_id):
    if request.method == 'DELETE':
        # installed_softwares = InstSoftwareModel.query.filter(InstSoftwareModel.software_id == software_id)
        installed_softwares = db.session.query(InstSoftwareModel).filter(InstSoftwareModel.software_id == software_id)
        db.session.commit()
        for software in installed_softwares:
            current_db_session = db.session.object_session(software)
            current_db_session.delete(software)
            current_db_session.commit()
        return {"message": f"Installed Software {software.software_id} successfully deleted."}

# api.add_resource(resources.UserLogin, '/JWTAuth/login')
# api.add_resource(resources.UserLogoutAccess, '/JWTAuth/logout/access')
# api.add_resource(resources.UserLogoutRefresh, '/JWTAuth/logout/refresh')
# api.add_resource(resources.TokenRefresh, '/JWTAuth/token/refresh')
# api.add_resource(resources.SecretResource, '/JWTAuth/secret')
# api.add_resource(resources.InstallSoftware, '/JWTAuth/computer/software')
# api.add_resource(resources.FindComputerBySoftwareID, '/JWTAuth/computer/software/id')
# api.add_resource(resources.DeleteSoftwareFromComputerBYPCID, '/JWTAuth/computer/software/delete')
# api.add_resource(resources.InstallPcie, '/JWTAuth/computer/pcie')
# api.add_resource(resources.InstallCPU, '/JWTAuth/computer/processor')
# api.add_resource(resources.InstallRam, '/JWTAuth/computer/ram')
# api.add_resource(resources.ComputerAdd, '/JWTAuth/computer/add')
# api.add_resource(resources.AllComputers, '/JWTAuth/computer/all')
# api.add_resource(resources.DeleteComputer, '/JWTAuth/computer/delete')
# api.add_resource(resources.UpdateComputerName, '/JWTAuth/computer/name')
# api.add_resource(resources.UpdateComputerEDV, '/JWTAuth/computer/edv')#
# api.add_resource(resources.UpdateComputerRoom, '/JWTAuth/computer/room')
# api.add_resource(resources.UpdateComputerUser, '/JWTAuth/computer/user')
# api.add_resource(resources.UpdateComputerIP, '/JWTAuth/computer/ip')
# a#pi.add_resource(resources.UpdateComputerOS, '/JWTAuth/computer/os')
# api.add_resource(resources.UpdateComputerType, '/JWTAuth/computer/type')
# api.add_resource(resources.UpdateComputerMotherboard, '/JWTAuth/computer/motherboard')
# api.add_resource(resources.UpdateComputerNote, '/JWTAuth/computer/note')
# api.add_resource(resources.UpdateComputerBorrowable, '/JWTAuth/computer/borrowable')
# api.add_resource(resources.UpdateComputerStorage, '/JWTAuth/computer/storage')
# api.add_resource(resources.AllCompleteComputer, '/JWTAuth/computer/allcomplete')#
# api.add_resource(resources.FindComputerByUserID, '/JWTAuth/computer/userid')
# api.add_resource(resources.FindComputerByRoomID, '/JWTAuth/computer/roomid')
# api.add_resource(resources.FindComputerByMotherboardID, '/JWTAuth/computer/mainboardid')
# api.add_resource(resources.UpdateUserFirstname, '/JWTAuth/user/firstname')
# api.add_resource(resources.UpdateUserLastname, '/JWTAuth/user/lastname')
# api.add_resource(resources.UpdateUserEmail, '/JWTAuth/user/email')
# api.add_resource(resources.UpdateUserRole, '/JWTAuth/user/role')
# api.add_resource(resources.SoftwareBySoftwareID, '/JWTAuth/software/software')
# api.add_resource(resources.DeleteSoftwareFromAllComputer, '/JWTAuth/software/deleteall')
# api.add_resource(resources.DeleteSoftware, '/JWTAuth/software/delete')
# api.add_resource(resources.DeleteOsByID, '/JWTAuth/os/delete')
# api.add_resource(resources.GetComputerByComputerID, '/JWTAuth/computer/id')
# api.add_resource(resources.DeleteMainboardByMainboardID, '/JWTAuth/mainboard/delete')
# api.add_resource(resources.DeletePCIEByPCIEID, '/JWTAuth/pcie/delete')
# api.add_resource(resources.DeleteProcessorByProcessorID, '/JWTAuth/processor/delete')
# a#pi.add_resource(resources.DeleteRamByRamID, '/JWTAuth/ram/delete')
# api.add_resource(resources.UpdateOSName, '/JWTAuth/os/name')
# api.add_resource(resources.UpdateOSVersion, '/JWTAuth/os/version')
# api.add_resource(resources.UpdateSoftwareName, '/JWTAuth/software/name')
# api.add_resource(resources.UpdateSoftwareDescription, '/JWTAuth/software/description')
