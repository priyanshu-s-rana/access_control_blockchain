import hashlib
import math
import secrets  # Use secrets for cryptographically secure random numbers
from typing import Tuple, Dict, Optional

# Using pycryptodome for prime generation and primality testing
from Crypto.Util import number

# --- Constants ---
# PRIME_CERTAINTY_ITERATIONS = 5 # This was used for K, which is not a valid param for number.isPrime
DEFAULT_ACCUMULATED_PRIME_SIZE_BITS = 256 # Default if not specified

# --- Utility Functions ---

'''
Generate a random big integer in the range [min_val, max_val).
This is a secure random number generator.
'''
def get_random_bigint(min_val: int, max_val: int) -> int:
    if min_val >= max_val:
        raise ValueError("max_val must be strictly greater than min_val")
    range_val = max_val - min_val
    return min_val + secrets.randbelow(range_val)

'''
Generate a secure random big integer of specified bit length.
'''
def get_random_bigint_bits(bit_length: int) -> int:
    if bit_length <= 0:
        raise ValueError("bit_length must be positive")
    val = secrets.randbits(bit_length - 1) | (1 << (bit_length - 1))
    return val

'''
Generate a large prime number of specified bit length.
'''
def generate_large_prime(bit_length: int) -> int:
    if bit_length < 16: # PyCryptodome's getPrime needs at least 2 bits, but practically much more
        raise ValueError("Bit length should be substantially larger for secure prime generation")
    # randfunc=secrets.token_bytes is good for providing a strong random source
    prime = number.getPrime(bit_length, randfunc=secrets.token_bytes)
    return prime

def generate_two_large_distinct_primes(bit_length: int) -> Tuple[int, int]:
    p = generate_large_prime(bit_length)
    q = generate_large_prime(bit_length)
    while p == q:
        q = generate_large_prime(bit_length)
    return p, q


'''
Args:
    x: int - The input integer to hash
    bit_length: int - The desired bit length of the output prime
Returns:
    int - A prime number of the specified bit length
'''
def hash_to_length(x: int, bit_length: int) -> int:
    '''
    Generate a hash of the input integer x and return an integer of the specified bit length.
    '''
    if bit_length <= 0:
        raise ValueError("bit_length must be positive")
    num_blocks = math.ceil(bit_length / 256.0) # SHA-256 produces 256 bits
    hashed_bytes = b''
    for i in range(int(num_blocks)): # Ensure num_blocks is int for range
        input_bytes = str(x + i).encode('utf-8')
        hashed_bytes += hashlib.sha256(input_bytes).digest()
    
    required_bytes = math.ceil(bit_length / 8.0)
    if len(hashed_bytes) > int(required_bytes): # Ensure required_bytes is int
        hashed_bytes = hashed_bytes[:int(required_bytes)]
        
    result_int = int.from_bytes(hashed_bytes, byteorder='big')
    
    if bit_length > 0:
        # Ensure the number is within the desired bit length by masking
        # Also, to ensure it's close to the bit length, we can set the top bit
        # if the result is smaller than 2^(bit_length-1)
        mask = (1 << bit_length) - 1
        result_int &= mask
        # if bit_length > 1 and result_int < (1 << (bit_length - 1)): # Optional: ensure top bit is set
        #     result_int |= (1 << (bit_length - 1))
            
    return result_int

'''
Args:
    x: int - The input integer to hash
    bit_length: int - The desired bit length of the output prime
    init_nonce: int - The initial nonce to start searching for a prime
Returns:
    Tuple[int, int] - A tuple containing the found prime and the nonce used to find it
'''
def hash_to_prime(x: int, bit_length: int, init_nonce: int = 0) -> Tuple[int, int]:
    '''
    Generate a prime number from the input integer x and a nonce.
    The nonce is used to find a prime number by hashing the input with the nonce.
    The function will return the first prime found and the nonce used to find it.
    '''
    nonce = init_nonce
    max_attempts_per_init_nonce = 100000 # Safety break for a specific init_nonce
    attempts_for_current_init_nonce = 0

    while True:
        num_to_test = hash_to_length(x + nonce, bit_length)
        
        if num_to_test < 2: # Primes must be >= 2
            nonce += 1
            if init_nonce != 0: attempts_for_current_init_nonce +=1
            continue
        
        # PyCryptodome's isPrime handles even numbers correctly (only 2 is an even prime)
        # No need to manually make it odd unless num_to_test is 2.
        # If num_to_test is 2, it's prime.
        if num_to_test == 2:
            return num_to_test, nonce

        # For numbers > 2, they must be odd to be prime.
        # hash_to_length might produce an even number.
        if num_to_test % 2 == 0:
            # # print(f"Debug: num_to_test {num_to_test} was even for x={x}, nonce={nonce}. Skipping.")
            nonce += 1 # Try next nonce to get a new hash
            if init_nonce != 0: attempts_for_current_init_nonce +=1
            continue

        # MODIFICATION: Removed the 'K' argument
        if number.isPrime(num_to_test): 
            return num_to_test, nonce
        
        nonce += 1
        if init_nonce != 0:
            attempts_for_current_init_nonce +=1
            if attempts_for_current_init_nonce > max_attempts_per_init_nonce:
                raise ValueError(f"Could not find prime for {x} with nonce starting at {init_nonce} after {max_attempts_per_init_nonce} attempts.")
        elif nonce > init_nonce + 500000: # General safety break if searching from 0
            raise ValueError(f"Could not find prime for {x} after many attempts starting from nonce {init_nonce}.")


class RsaAccumulator:
    def __init__(self, rsa_key_size_bits: int = 256, N: Optional[int] = None, a0: Optional[int] = None, 
                data: Optional[Dict[int, int]] = None, 
                element_prime_bits: int = DEFAULT_ACCUMULATED_PRIME_SIZE_BITS):
        
        if rsa_key_size_bits % 2 != 0:
            raise ValueError("rsa_key_size_bits must be an even number.")

        self._rsa_prime_size_bits = rsa_key_size_bits // 2
        self._accumulated_prime_size_bits = element_prime_bits

        if N is None or a0 is None:
            # print("N or a0 not provided, generating new RSA parameters...")
            p, q = generate_two_large_distinct_primes(self._rsa_prime_size_bits)
            self._n = p * q
            self._a0 = get_random_bigint(1, self._n) # Ensure a0 is in Z_N^*, not 0 or 1 typically
            if self._a0 <= 1: # Simple check, more robust would be GCD check if N is not prime product
                self._a0 = get_random_bigint(2, self._n) # Try again to get a better base
        else:
            # print("Using provided N and a0.")
            self._n = N
            self._a0 = a0
        
        self._a = self._a0 
        self._data: Dict[int, int] = {} 

        # print(f"Initialized RSA Accumulator. N={self._n}, A0={self._a0}, ElementPrimeBits={self._accumulated_prime_size_bits}")

        if data:
            # print(f"DEBUG __init__: Initializing with existing data: {data}")
            current_product_of_primes = 1
            temp_data_storage = {} 

            for elem, elem_nonce in data.items():
                # When re-initializing, use the stored nonce to find the prime
                h_elem, nonce_check = hash_to_prime(elem, self._accumulated_prime_size_bits, elem_nonce)
                #if nonce_check != elem_nonce:
                    # This is a critical issue: it means the stored nonce doesn't actually produce the prime
                    # or hash_to_prime found it earlier. This indicates a problem with how nonces were stored or derived.
                    # For robust reconstruction, we must use the prime derived from the *exact* stored nonce.
                    # The current hash_to_prime logic might need adjustment if init_nonce is not the first one.
                    # One way to ensure this is to make hash_to_prime return failure if init_nonce is given and
                    # the prime is not found *with that specific nonce*.
                    # For now, let's assume hash_to_prime correctly uses init_nonce if provided.
                    # print(f"Warning: Nonce check mismatch for element {elem} during re-init. Stored: {elem_nonce}, Checked: {nonce_check}. Using prime from nonce {nonce_check}.")
                    # This might be okay if hash_to_prime guarantees it returns the prime for init_nonce if one exists at that nonce
                
                current_product_of_primes *= h_elem
                temp_data_storage[elem] = elem_nonce 
            
            if current_product_of_primes != 1: 
                self._a = pow(self._a0, current_product_of_primes, self._n)
            
            self._data = temp_data_storage 
            # print(f"DEBUG __init__: Accumulator re-computed. New self._a = {self._a}")
        else:
            z = None
            # print("DEBUG __init__: Initializing new/empty accumulator. self._a remains self._a0.")

    @property
    def n(self) -> int:
        return self._n

    @property
    def a0(self) -> int:
        return self._a0

    @property
    def current_accumulator_value(self) -> int:
        return self._a

    def size(self) -> int:
        return len(self._data)

    def get_elements(self) -> list[int]:
        return list(self._data.keys())

    def get_nonces(self) -> list[int]:
        return list(self._data.values())
        
    def get_nonce(self, x: int) -> Optional[int]:
        return self._data.get(x)
    
    def to_dict(self):
        return {
            'n': self._n,
            'a0': self._a0,
            'a': self._a,
            'data': self._data
        }
    
    @classmethod
    def from_dict(self, data: dict) :
        n = data['n']
        a0 = data['a0']
        a = data['a']
        data_dict = {int(k): int(v) for k, v in data['data'].items()}
        return RsaAccumulator(N=n, a0=a0, data=data_dict, element_prime_bits=DEFAULT_ACCUMULATED_PRIME_SIZE_BITS)
        

    def _get_prime_representation(self, x: int, nonce: Optional[int] = None) -> int:
        if nonce is None:
            stored_nonce = self.get_nonce(x)
            if stored_nonce is None:
                raise KeyError(f"Element {x} or its nonce not found in accumulator for _get_prime_representation.")
            # Use the stored nonce to get the prime
            prime, nonce_check = hash_to_prime(x, self._accumulated_prime_size_bits, stored_nonce)
            if nonce_check != stored_nonce:
                # This can happen if hash_to_prime's init_nonce logic isn't strict.
                # For safety, re-verify by finding the canonical prime from nonce 0.
                _, canonical_nonce = hash_to_prime(x, self._accumulated_prime_size_bits, 0)
                if canonical_nonce != stored_nonce:
                    raise ValueError(f"Nonce inconsistency for element {x}. Stored: {stored_nonce}, Canonical: {canonical_nonce}")
            return prime
        else:
            # If a nonce is explicitly provided, use it to find the prime
            prime, _ = hash_to_prime(x, self._accumulated_prime_size_bits, nonce)
            return prime


    def add(self, x: int) -> int:
        if x in self._data:
            # print(f"Element {x} already in accumulator. No changes made.")
            return self._a

        # print(f"Adding element {x}...")
        # When adding, find the first nonce that yields a prime, starting from 0
        h_x, nonce = hash_to_prime(x, self._accumulated_prime_size_bits, 0) 

        self._a = pow(self._a, h_x, self._n)
        self._data[x] = nonce 
        # print(f" Element {x} added with nonce {nonce} (prime {h_x}). New A: {self._a}")
        return self._a

    def _iterate_and_get_product_of_primes(self, element_to_exclude: Optional[int] = None) -> int:
        '''
        Iterate through the stored elements and calculate the product of their primes.
        '''
        product = 1
        for k, stored_nonce_for_k in self._data.items():
            if element_to_exclude is not None and k == element_to_exclude:
                continue
            
            h_k = self._get_prime_representation(k, stored_nonce_for_k)
            product *= h_k
        return product

    def prove_membership(self, x: int) -> Optional[int]:
        '''
        Generate a membership proof for the element x.
        '''
        if x not in self._data:
            # print(f"Element {x} not found in accumulator. Cannot generate proof.")
            return None

        # print(f"Generating membership proof for {x}...")
        product_of_other_primes = self._iterate_and_get_product_of_primes(element_to_exclude=x)
        
        witness = pow(self._a0, product_of_other_primes, self._n)
        # print(f" Witness generated: {witness}")
        return witness

    def delete(self, x: int) -> int:
        if x not in self._data:
            # print(f"Element {x} not in accumulator. Cannot delete.")
            return self._a

        # print(f"Deleting element {x}...")
        removed_nonce = self._data.pop(x)
        # print(f" Element {x} (nonce {removed_nonce}) removed from tracking.")

        product_of_remaining_primes = self._iterate_and_get_product_of_primes()
        # Accumulator value is A0 to the power of product of remaining primes
        self._a = pow(self._a0, product_of_remaining_primes, self._n) 

        # print(f" Accumulator updated after deletion. New A: {self._a}")
        return self._a

    @staticmethod
    def verify_membership(
        accumulator_value: int, 
        x: int,
        nonce_for_x: int,       
        witness: int,           
        n: int,
        accumulated_prime_size_bits: int 
    ) -> bool:
        '''
        Verify the membership of x in the accumulator using the provided witness.
        '''
        # print(f"Verifying membership for {x} with nonce {nonce_for_x} using {accumulated_prime_size_bits}-bit primes...")
        try:
            # Re-derive the prime h_x for element x using its specific stored nonce_for_x and bit size
            h_x, nonce_check = hash_to_prime(x, accumulated_prime_size_bits, nonce_for_x)

            # If hash_to_prime had to search (i.e., nonce_check != nonce_for_x), it implies
            # that the provided nonce_for_x was not the one that originally generated the prime.
            # This check ensures we use the prime corresponding to the *actual* nonce.
            if nonce_check != nonce_for_x:
                # This is a more robust check: find the canonical nonce from scratch
                _, canonical_nonce = hash_to_prime(x, accumulated_prime_size_bits, 0)
                if canonical_nonce != nonce_for_x:
                    # print(f" Verification Failed: Nonce mismatch. Provided nonce_for_x ({nonce_for_x}) "
                        #f"does not match the canonical nonce ({canonical_nonce}) "
                        #f"that generates a prime for element {x} with {accumulated_prime_size_bits} bits.")
                    return False
                # If canonical_nonce IS nonce_for_x, then h_x derived with init_nonce=nonce_for_x is correct.
            
            # print(f"  Derived prime h_x for verification: {h_x} (using nonce {nonce_for_x})")
            # print(f"  Witness (w): {witness}")
            # print(f"  N: {n}")
            # print(f"  Accumulator value (A) to check against: {accumulator_value}")

            expected_a = pow(witness, h_x, n)
            # print(f"  Calculated (witness ^ h_x mod N): {expected_a}")
            
            is_valid = (expected_a == accumulator_value)

            # print(f"  Verification result: {is_valid}")
            return is_valid

        except Exception as e:
            # print(f"Error during verification: {e}")
            return False

# if __name__ == "__main__":
#     # Example usage
#     a0_val=34159902467098801166336437294293264097225945511215182269642892110133424424499
#     N_val=56676326342099385763132335423605869458942667779217078150541017090654611257191
#     data_val = {9966214013: 1} # Example data from your logs
    
#     # print("--- Test Case from Logs ---")
#     # Initialize with specific N, a0, data, and crucially the element_prime_bits used in verification
#     rsa_accumulator = RsaAccumulator(N=N_val, a0=a0_val, data=data_val, element_prime_bits=256)
    
#     test_element = 9966214013
#     test_nonce = rsa_accumulator.get_nonce(test_element) # Should be 1
    
#     if test_nonce is not None:
#         witness_val = rsa_accumulator.prove_membership(test_element)
#         if witness_val is not None:
#             # print(f"\nAttempting verification for element {test_element} with nonce {test_nonce}:")
#             is_member = RsaAccumulator.verify_membership(
#                 accumulator_value=rsa_accumulator.current_accumulator_value,
#                 x=test_element,
#                 nonce_for_x=test_nonce,
#                 witness=witness_val,
#                 n=rsa_accumulator.n,
#                 accumulated_prime_size_bits=256 # Match the bits used in verify_user
#             )
#             # print(f"Final verification in test.py: {is_member}")
#             assert is_member, "Verification failed for known member in test.py"
#         else:
#             # print(f"Could not generate witness for {test_element} in test.py")
#     else:
#         # print(f"Could not get nonce for {test_element} in test.py")

    # # print("\n--- Original Example Usage (for general testing) ---")
    # acc = RsaAccumulator(rsa_key_size_bits=512, element_prime_bits=128) # Using 128 for element primes here
    # # print(f"Initial Accumulator A = {acc.current_accumulator_value}")
    # # print("-" * 30)

    # elements_to_add = [123, 678, 987, 112]
    # for elem in elements_to_add:
    #     acc.add(elem)
    # # print("-" * 30)
    # # print(f"Accumulator size: {acc.size()}")
    # # print(f"Final Accumulator A = {acc.current_accumulator_value}")
    # # print(f"Accumulated elements and nonces: {acc._data}")
    # # print("-" * 30)

    # element_to_prove = 678
    # nonce_prove = acc.get_nonce(element_to_prove)
    # if nonce_prove is not None:
    #     witness = acc.prove_membership(element_to_prove)
    #     if witness is not None:
    #         is_valid = RsaAccumulator.verify_membership(
    #             acc.current_accumulator_value,
    #             element_to_prove,
    #             nonce_prove,
    #             witness,
    #             acc.n,
    #             acc._accumulated_prime_size_bits # Pass the bits used by this acc instance
    #         )
    #         # print(f"Membership proof for {element_to_prove} verification: {is_valid}")
    #         assert is_valid 
    # else:
    #     # print(f"Could not get nonce for {element_to_prove}")

# 50288727366554689944573622666380926638627053994442510168273113567069886874581

# 88087546787242427424777777276845458651257697242435401538577404781753930094119