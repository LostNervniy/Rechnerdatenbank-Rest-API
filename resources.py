from flask_restx import Resource, reqparse, Api

from Models.UserModel import UserModel
from Models.ComputerCompleteModel import ComputerCompleteModel
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
from Models.RevokedTokenModel import RevokedTokenModel
from Models.RoomModel import RoomModel
from Models.SoftwareModel import SoftwareModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required,
                                get_jwt_identity, get_raw_jwt, JWTManager)
import json

Userparser = reqparse.RequestParser()
Userparser.add_argument('email')
Userparser.add_argument('passwd')
Userparser.add_argument('lastname')
Userparser.add_argument('firstname')
Userparser.add_argument('role')
Userparser.add_argument('user_id')

Softwareparser = reqparse.RequestParser()
Softwareparser.add_argument('software_id')
Softwareparser.add_argument('description')
Softwareparser.add_argument('name')

Roomparser = reqparse.RequestParser()
Roomparser.add_argument('description')
Roomparser.add_argument('name')
Roomparser.add_argument('etage')
Roomparser.add_argument('room_id')

Hardwareparser = reqparse.RequestParser()
Hardwareparser.add_argument('producer')
Hardwareparser.add_argument('name')
Hardwareparser.add_argument('chipset')
Hardwareparser.add_argument('socket')
Hardwareparser.add_argument('sockets')
Hardwareparser.add_argument('dimmslots')
Hardwareparser.add_argument('pcieslots')
Hardwareparser.add_argument('m2slots')
Hardwareparser.add_argument('sataconnectors')
Hardwareparser.add_argument('formfactor')
Hardwareparser.add_argument('type')
Hardwareparser.add_argument('clock')
Hardwareparser.add_argument('architecture')
Hardwareparser.add_argument('standard')
Hardwareparser.add_argument('frequency')
Hardwareparser.add_argument('capacity')
Hardwareparser.add_argument('ddr')
Hardwareparser.add_argument('mainboard_id')
Hardwareparser.add_argument('pcie_id')
Hardwareparser.add_argument('processor_id')
Hardwareparser.add_argument('ram_id')

OSparser = reqparse.RequestParser()
OSparser.add_argument('name')
OSparser.add_argument('architecture')
OSparser.add_argument('version')
OSparser.add_argument('os_id')

InstalledParser = reqparse.RequestParser()
InstalledParser.add_argument('computer_id')
InstalledParser.add_argument('processor_id')
InstalledParser.add_argument('pcie_id')
InstalledParser.add_argument('ram_id')
InstalledParser.add_argument('software_id')
InstalledParser.add_argument('s_installed_id')
InstalledParser.add_argument('p_installed_id')
InstalledParser.add_argument('r_installed_id')
InstalledParser.add_argument('edv')

ComputerParser = reqparse.RequestParser()
ComputerParser.add_argument('computer_id')
ComputerParser.add_argument('name')
ComputerParser.add_argument('edv')
ComputerParser.add_argument('room')
ComputerParser.add_argument('user')
ComputerParser.add_argument('ip')
ComputerParser.add_argument('os')
ComputerParser.add_argument('bit')
ComputerParser.add_argument('type')
ComputerParser.add_argument('mainboard')
ComputerParser.add_argument('description')
ComputerParser.add_argument('rentable')
ComputerParser.add_argument('storage')


class UserRegistration(Resource):
    def post(self):
        data = Userparser.parse_args()

        new_user = UserModel(
            email=data['email'],
            firstname=data['firstname'],
            lastname=data['lastname'],
            role=data['role'],
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data['email'])
            refresh_token = create_refresh_token(identity=data['email'])
            return {
                'message': 'User {} was created'.format(data['email']),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except:
            return {'message': 'Something went wrong'}, 500


class UpdateUserFirstname(Resource):
    def put(self):
        data = Userparser.parse_args()
        user_id = data['user_id']
        firstname = data['firstname']
        return UserModel.update_userfirstname_user_id(user_id, firstname)


class UpdateUserLastname(Resource):
    def put(self):
        data = Userparser.parse_args()
        user_id = data['user_id']
        lastname = data['lastname']
        return UserModel.update_userlastname_user_id(user_id, lastname)


class UpdateUserEmail(Resource):
    def put(self):
        data = Userparser.parse_args()
        user_id = data['user_id']
        email = data['email']
        return UserModel.update_useremail_user_id(user_id, email)


class UpdateUserRole(Resource):
    def put(self):
        data = Userparser.parse_args()
        user_id = data['user_id']
        role = data['role']
        return UserModel.update_userrole_user_id(user_id, role)


class UserLogin(Resource):
    def post(self):
        data = Userparser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}

        if UserModel.verify_hash(data['password'], current_user.passwd):
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'message': 'Wrong credentials'}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()


class UserByID(Resource):
    def get(self):
        data = Userparser.parse_args()
        return UserModel.return_user_by_id(data['user_id'])


class UserDelete(Resource):
    def delete(self):
        data = Userparser.parse_args()
        return UserModel.delete_user(data['user_id'])


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}


class SoftwareAdd(Resource):
    def post(self):
        data = Softwareparser.parse_args()

        new_software = SoftwareModel(
            name=data['name'],
            description=data['description'],
        )

        try:
            new_software.save_to_db()
            return {
                'message': 'Software {} was created'.format(data['name'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class AllSoftware(Resource):
    def get(self):
        return SoftwareModel.return_all()


class DeleteSoftware(Resource):
    def delete(self):
        data = Softwareparser.parse_args()
        SoftwareModel.delete_software(data['software_id'])


class RoomAdd(Resource):
    def post(self):
        data = Roomparser.parse_args()

        new_room = RoomModel(
            name=data['name'],
            etage=data['etage'],
            description=data['description'],
        )

        try:
            new_room.save_to_db()
            return {
                'message': 'Room {} was created'.format(data['name'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class AllRooms(Resource):
    def get(self):
        return RoomModel.return_all()


class RoomByID(Resource):
    def get(self):
        data = Roomparser.parse_args()
        return RoomModel.return_room_by_id(data['room_id'])


class RoomDelete(Resource):
    def delete(self):
        data = Roomparser.parse_args()
        return RoomModel.delete_room(data['room_id'])


class RamAdd(Resource):
    def post(self):
        data = Hardwareparser.parse_args()

        new_ram = RamModel(
            name=data['name'],
            producer=data['producer'],
            standard=data['standard'],
            frequency=data['frequency'],
            capacity=data['capacity']
        )

        try:
            new_ram.save_to_db()
            return {
                'message': 'RAM {} was created'.format(data['name'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class AllRams(Resource):
    def get(self):
        return RamModel.return_all()


class FindRamStandard(Resource):
    def get(self):
        data = Hardwareparser.parse_args()
        standard = data['standard']
        print(standard)
        return RamModel.return_ram_by_standard(standard)


class InstalledRam(Resource):
    def get(self):
        data = ComputerParser.parse_args()
        pcid = data['computer_id']
        return RamModel.return_installed_by_pcid(pcid)


class ProcessorAdd(Resource):
    def post(self):
        data = Hardwareparser.parse_args()

        new_cpu = ProcessorModel(
            name=data['name'],
            producer=data['producer'],
            clock=data['clock'],
            architecture=data['architecture'],
            socket=data['socket'],
        )

        try:
            new_cpu.save_to_db()
            return {
                'message': 'CPU {} was created'.format(data['name'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class AllProcessors(Resource):
    def get(self):
        return ProcessorModel.return_all()


class FindProcessorSocket(Resource):
    def get(self):
        data = Hardwareparser.parse_args()
        socket = data['socket']
        return ProcessorModel.return_processor_by_socket(socket)


class InstalledProcessor(Resource):
    def get(self):
        data = ComputerParser.parse_args()
        pcid = data['computer_id']
        return ProcessorModel.return_installed_by_pcid(pcid)


class PcieAdd(Resource):
    def post(self):
        data = Hardwareparser.parse_args()

        new_pcie = PcieModel(
            name=data['name'],
            producer=data['producer'],
            type=data['type'],
        )

        try:
            new_pcie.save_to_db()
            return {
                'message': 'PCIe {} was created'.format(data['name'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class AllPcies(Resource):
    def get(self):
        return PcieModel.return_all()


class InstalledPcie(Resource):
    def get(self):
        data = ComputerParser.parse_args()
        pcid = data['computer_id']
        return PcieModel.return_installed_by_pcid(pcid)


class MainboardAdd(Resource):
    def post(self):
        data = Hardwareparser.parse_args()

        new_mainboard = MainboardModel(
            name=data['name'],
            producer=data['producer'],
            socket=data['socket'],
            sockets=data['sockets'],
            chipset=data['chipset'],
            dimmslots=data['dimmslots'],
            pcieslots=data['pcieslots'],
            m2slots=data['m2slots'],
            sataconnectors=data['sataconnectors'],
            formfactor=data['formfactor'],
            ddr=data['ddr'],
        )

        try:
            new_mainboard.save_to_db()
            return {
                'message': 'Mainboard {} was created'.format(data['name'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class AllMainboards(Resource):
    def get(self):
        return MainboardModel.return_all()


class InstalledMainboard(Resource):
    def get(self):
        data = ComputerParser.parse_args()
        pcid = data['computer_id']
        return MainboardModel.return_installed_by_pcid(pcid)


class OSAdd(Resource):
    def post(self):

        data = OSparser.parse_args()

        new_os = OSModel(
            name=data['name'],
            version=data['version'],
        )

        try:
            new_os.save_to_db()
            return {
                'message': 'OS {} was created'.format(data['name'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class AllOSs(Resource):
    def get(self):
        return OSModel.return_all()


class DeleteOsByID(Resource):
    def delete(self):
        data = OSparser.parse_args()
        return OSModel.delete_os_by_id(data['os_id'])


class OSByID(Resource):
    def get(self):
        data = OSparser.parse_args()
        return OSModel.return_os_by_id(data['os_id'])


class InstallCPU(Resource):
    def post(self):

        data = InstalledParser.parse_args()
        computer_id = ComputerModel.return_id_for_edv(data["edv"])

        new_installation = InstProcessorModel(
            processor_id=data['processor_id'],
            computer_id=computer_id['computer'][0]['computer_id'],
            p_installed_id=data['p_installed_id']
        )

        try:
            new_installation.save_to_db()
            return {
                'message': 'Installation {} was created'.format(data['p_installed_id'])
            }
        except:
            return {'message': 'Something went wrong'}, 500

    def put(self):
        data = InstalledParser.parse_args()
        computer_id = data['computer_id']
        processor_id = data['processor_id']

        new_installation = InstProcessorModel(
            processor_id=processor_id,
            computer_id=computer_id,
            p_installed_id=data['p_installed_id']
        )

        InstProcessorModel.deinstall_id(computer_id)
        new_installation.save_to_db()


class InstallPcie(Resource):
    def post(self):

        data = InstalledParser.parse_args()
        computer_id = ComputerModel.return_id_for_edv(data["edv"])

        new_installation = InstPcieModel(
            pcie_id=data['pcie_id'],
            computer_id=computer_id['computer'][0]['computer_id'],
            p_installed_id=data['p_installed_id']
        )

        try:
            new_installation.save_to_db()
            return {
                'message': 'Installation {} was created'.format(data['p_installed_id'])
            }
        except:
            return {'message': 'Something went wrong'}, 500

    def put(self):
        data = InstalledParser.parse_args()
        computer_id = data['computer_id']
        pcie_id = data['pcie_id']

        new_installation = InstPcieModel(
            pcie_id=pcie_id,
            computer_id=computer_id,
            p_installed_id=data['p_installed_id']
        )

        InstPcieModel.deinstall_id(computer_id)
        new_installation.save_to_db()


class InstallSoftware(Resource):
    def post(self):

        data = InstalledParser.parse_args()
        computer_id = ComputerModel.return_id_for_edv(data["edv"])

        new_installation = InstSoftwareModel(
            software_id=data['software_id'],
            computer_id=computer_id['computer'][0]['computer_id'],
            s_installed_id=data['s_installed_id']
        )

        try:
            new_installation.save_to_db()
            return {
                'message': 'Installation {} was created'.format(data['s_installed_id'])
            }
        except:
            return {'message': 'Something went wrong'}, 500

    def put(self):
        data = InstalledParser.parse_args()
        computer_id = data['computer_id']
        software_id = data['software_id']

        new_installation = InstSoftwareModel(
            software_id=software_id,
            computer_id=computer_id,
            s_installed_id=data['s_installed_id']
        )

        InstSoftwareModel.deinstall_id(computer_id)
        new_installation.save_to_db()


class DeleteSoftwareFromComputerBYPCID(Resource):
    def delete(self):
        data = InstalledParser.parse_args()
        computer_id = data['computer_id']
        software_id = data['software_id']
        return InstSoftwareModel.deinstall_id(computer_id, software_id)


class InstallRam(Resource):
    def post(self):

        data = InstalledParser.parse_args()
        computer_id = ComputerModel.return_id_for_edv(data["edv"])
        print(computer_id)

        new_installation = InstRamModel(
            ram_id=data['ram_id'],
            computer_id=computer_id['computer'][0]['computer_id'],
            r_installed_id=data['r_installed_id']
        )

        try:
            new_installation.save_to_db()
            return {
                'message': 'Installation {} was created'.format(data['r_installed_id'])
            }
        except:
            return {'message': 'Something went wrong'}, 500

    def put(self):
        data = InstalledParser.parse_args()
        computer_id = data['computer_id']
        ram_id = data['ram_id']

        new_installation = InstRamModel(
            ram_id=ram_id,
            computer_id=computer_id,
            r_installed_id=data['r_installed_id']
        )

        InstRamModel.deinstall_id(computer_id)
        new_installation.save_to_db()


class ComputerAdd(Resource):
    def post(self):
        data = ComputerParser.parse_args()

        if data['rentable'] == 'Ja':
            data['rentable'] = 1
        else:
            data['rentable'] = 0
        if data['description'] == 'null':
            data['description'] = ' '
        new_computer = ComputerModel(
            computer_id=data['computer_id'],
            name=data['name'],
            edv=data['edv'],
            room_id=data['room'],
            user_id=data['user'],
            ip=data['ip'],
            os_id=data['os'],
            type=data['type'],
            motherboard_id=data['mainboard'],
            note=data['description'],
            borrowable=data['rentable'],
            storage=data['storage'],
        )
        try:
            new_computer.save_to_db()
            return {
                'message': 'Computer {} was created'.format(data['edv'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class AllComputers(Resource):
    def get(self):
        return ComputerModel.return_all()


class DeleteComputer(Resource):
    def delete(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        InstPcieModel.deinstall_id(computer_id)
        InstRamModel.deinstall_id(computer_id)
        InstProcessorModel.deinstall_id(computer_id)
        return ComputerModel.delete_pc(computer_id)


class UpdateComputerName(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        name = data['name']
        return ComputerModel.update_pc_name(computer_id, name)


class UpdateComputerEDV(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        edv = data['edv']
        return ComputerModel.update_pc_edv(computer_id, edv)


class UpdateComputerRoom(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        room = data['room']
        return ComputerModel.update_pc_room_id(computer_id, room)


class UpdateComputerUser(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        user = data['user']
        return ComputerModel.update_pc_user_id(computer_id, user)


class UpdateComputerIP(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        ip = data['ip']
        return ComputerModel.update_pc_ip(computer_id, ip)


class UpdateComputerOS(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        os = data['os']
        return ComputerModel.update_pc_os_id(computer_id, os)


class UpdateComputerType(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        type = data['type']
        return ComputerModel.update_pc_type(computer_id, type)


class UpdateComputerMotherboard(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        motherboard = data['mainboard']
        return ComputerModel.update_pc_motherboard_id(computer_id, motherboard)


class UpdateComputerNote(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        note = data['description']
        return ComputerModel.update_pc_note(computer_id, note)


class UpdateComputerBorrowable(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        borrowable = data['rentable']
        return ComputerModel.update_pc_borrowable(computer_id, borrowable)


class UpdateOSName(Resource):
    def put(self):
        data = OSparser.parse_args()
        os_id = data['os_id']
        name = data['name']
        return OSModel.update_os_name(os_id, name)


class UpdateOSVersion(Resource):
    def put(self):
        data = OSparser.parse_args()
        os_id = data['os_id']
        version = data['version']
        return OSModel.update_os_version(os_id, version)


class UpdateSoftwareName(Resource):
    def put(self):
        data = Softwareparser.parse_args()
        software_id = data['software_id']
        name = data['name']
        return SoftwareModel.update_software_name(software_id, name)


class UpdateSoftwareDescription(Resource):
    def put(self):
        data = Softwareparser.parse_args()
        software_id = data['software_id']
        description = data['description']
        return SoftwareModel.update_software_description(software_id, description)


class UpdateComputerStorage(Resource):
    def put(self):
        data = ComputerParser.parse_args()
        computer_id = data['computer_id']
        storage = data['storage']
        return ComputerModel.update_pc_storage(computer_id, storage)


class FindComputerBySoftwareID(Resource):
    def get(self):
        data = InstalledParser.parse_args()
        return InstSoftwareModel.return_computer_by_id(data['computer_id'])








class SoftwareBySoftwareID(Resource):
    def get(self):
        data = Softwareparser.parse_args()
        return SoftwareModel.return_by_sid(data['software_id'])


class DeleteSoftwareFromAllComputer(Resource):
    def delete(self):
        data = InstalledParser.parse_args()
        return InstSoftwareModel.delete_all_software_id(data['software_id'])


class GetComputerByComputerID(Resource):
    def get(self):
        data = ComputerParser.parse_args()
        return ComputerCompleteModel.return_by_computer_id(data['computer_id'])


class DeleteMainboardByMainboardID(Resource):
    def delete(self):
        data = Hardwareparser.parse_args()
        return MainboardModel.delete_mainboard_by_mainboard_id(data['mainboard_id'])


class DeletePCIEByPCIEID(Resource):
    def delete(self):
        data = Hardwareparser.parse_args()
        return PcieModel.delete_by_pcie_id(data['pcie_id'])


class DeleteProcessorByProcessorID(Resource):
    def delete(self):
        data = Hardwareparser.parse_args()
        return ProcessorModel.delete_processor_by_processor_id(data['processor_id'])


class DeleteRamByRamID(Resource):
    def delete(self):
        data = Hardwareparser.parse_args()
        return RamModel.delete_ram_by_ram_id(data['ram_id'])


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }
