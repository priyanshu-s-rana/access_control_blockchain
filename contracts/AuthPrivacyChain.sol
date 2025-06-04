pragma solidity >= 0.8.11 <= 0.8.11;

contract AuthPrivacyChain {
    
    struct RsaAccumulator {
        uint256 a0;
        uint256 N;
        uint256[] user_ids;
        uint256[] nonces; 
    }

    RsaAccumulator public acc;
    RsaAccumulator public default_acc;
    mapping(uint256 => string) public  datausers;
    mapping(uint256 => string) public directsharing;
    mapping(uint256 => string) public indirectsharing;
    mapping(uint256 => RsaAccumulator) public ds_acc_mapping;
    mapping(uint256 => RsaAccumulator) public ids_acc_mapping;

    uint userNum = 0;
    uint dsNum = 0;
    uint idsNum = 0;

    event DataUserCreated(uint256 indexed user_id);
    event AccumulatorCreated(RsaAccumulator indexed acc);

    function compareStrings(string memory a, string memory b) public pure returns (bool) {
        return (keccak256(abi.encodePacked((a))) == keccak256(abi.encodePacked((b))));
    }

    //add user details who are registered to access IOT and user password will be encrypted with sha512	
    function createDataUser(uint256 user_id, string memory user_type, string memory du) public {
        require(bytes(datausers[user_id]).length == 0, "User already exists");
        
        // Create user entry
        datausers[user_id] = du;	
        userNum++;

        
        // Initialize both direct and indirect sharing accumulators
        if (compareStrings(user_type, "direct")) {
            ds_acc_mapping[user_id] = default_acc;
        } else if (compareStrings(user_type, "indirect")) {
            ids_acc_mapping[user_id] = default_acc;
        }
        
        emit DataUserCreated(user_id);
    }
   //get user details
    function getDataUser(uint256 user_id) public view returns (string memory) {
        if (userNum > 0) {
            return datausers[user_id];
        }
        return "";
    }

    function setDirectSharing(uint256 user_id,string memory ds) public {
        directsharing[user_id] =ds;
        dsNum++;
    }

    function getDirectSharing(uint256 user_id) public view returns (string memory) {
        if (dsNum > 0) {
            return directsharing[user_id];
        }
        return "";
    }

    function setInDirectSharing(uint256 user_id,string memory ds) public {
        indirectsharing[user_id] = ds;
        idsNum++;
    }

    function getInDirectSharing(uint256 user_id) public view returns (string memory) {
        if (idsNum > 0) {
            return indirectsharing[user_id];
        }
        return "";
    }

    function getAccumulator(string memory user_type, uint256 user_id) public view returns (RsaAccumulator memory) {
        if (compareStrings(user_type, "direct")) {
            if (ds_acc_mapping[user_id].N == 0) {
                return default_acc;
            }
            return ds_acc_mapping[user_id];
        } else if (compareStrings(user_type, "indirect")) {
            if (ids_acc_mapping[user_id].N == 0) {
                return default_acc;
            }
            return ids_acc_mapping[user_id];
        }
        return acc;
    }

    function setAccumulator(string memory user_type, uint256 user_id, uint256 a0, uint256 N, uint256[] memory user_ids, uint256[] memory nonces) public {
        if (compareStrings(user_type, "direct")) {
            RsaAccumulator memory ds_acc;
            ds_acc.a0 = a0;
            ds_acc.N = N;
            ds_acc.user_ids = user_ids;
            ds_acc.nonces = nonces;
            ds_acc_mapping[user_id] = ds_acc;

            return;
        } else if (compareStrings(user_type, "indirect")) {
            RsaAccumulator memory ids_acc;
            ids_acc.a0 = a0;
            ids_acc.N = N;
            ids_acc.user_ids = user_ids;
            ids_acc.nonces = nonces;
            ids_acc_mapping[user_id] = ids_acc;

            return;
        }
        acc.a0 = a0;
        acc.N = N;
        acc.user_ids = user_ids;
        acc.nonces = nonces;
        emit AccumulatorCreated(acc);
    }

    constructor() {
        // Initialize the global accumulator with default values
        acc.a0=50288727366554689944573622666380926638627053994442510168273113567069886874581;
        acc.N=56676326342099385763132335423605869458942667779217078150541017090654611257191;
        acc.user_ids = new uint256[](0);
        acc.nonces = new uint256[](0);  

        // Initialize default values in mappings for new users
        default_acc.a0 = acc.a0;
        default_acc.N = acc.N;
        default_acc.user_ids = new uint256[](0);
        default_acc.nonces = new uint256[](0);
    }
}