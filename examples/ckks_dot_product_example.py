"""Example of CKKS multiplication."""

from ckks.ckks_decryptor import CKKSDecryptor
from ckks.ckks_encoder import CKKSEncoder
from ckks.ckks_encryptor import CKKSEncryptor
from ckks.ckks_evaluator import CKKSEvaluator
from ckks.ckks_key_generator import CKKSKeyGenerator
from ckks.ckks_parameters import CKKSParameters

def main():

    poly_degree = 8
    ciph_modulus = 1 << 600
    big_modulus = 1 << 1200
    scaling_factor = 1 << 30
    params = CKKSParameters(poly_degree=poly_degree,
                            ciph_modulus=ciph_modulus,
                            big_modulus=big_modulus,
                            scaling_factor=scaling_factor)
    key_generator = CKKSKeyGenerator(params)
    public_key = key_generator.public_key
    secret_key = key_generator.secret_key
    relin_key = key_generator.relin_key
    encoder = CKKSEncoder(params)
    encryptor = CKKSEncryptor(params, public_key, secret_key)
    decryptor = CKKSDecryptor(params, secret_key)
    evaluator = CKKSEvaluator(params)

    message1 = [0.5, 0.6, 0.7, 0.8]
    message2 = [0.2, 0.3, 0.4, 0.5]
    # at maximum, can encrypt vectors that are the half the size of the polynomial
    print(message1)
    print(message2)
    plain1 = encoder.encode(message1, scaling_factor)
    plain2 = encoder.encode(message2, scaling_factor)
    ciph1 = encryptor.encrypt(plain1)
    ciph2 = encryptor.encrypt(plain2)
    print("Addition test")
    ciph_add = evaluator.add(ciph1, ciph2)
    decrypted_add = decryptor.decrypt(ciph_add)
    decoded_add = encoder.decode(decrypted_add)
    print(decoded_add)
    print('Makes sense')
    print("Rotation test")
    print("Rotating message1 by 2")
    rot_key = key_generator.generate_rot_key(2)
    rotated_ciph = evaluator.rotate(ciph1, 2, rot_key)
    decrypted_rotated = decryptor.decrypt(rotated_ciph)
    decoded_rotated = encoder.decode(decrypted_rotated)
    print(decoded_rotated)
    print("Multiplication test")
    ciph_prod = evaluator.multiply(ciph1, ciph2, relin_key)
    decrypted_prod = decryptor.decrypt(ciph_prod)
    decoded_prod = encoder.decode(decrypted_prod)
    print(decoded_prod)
    print("dot product test")
    ciph_prod = evaluator.multiply(ciph1, ciph2, relin_key)
    # Now let's find the sum here too. Intuitively, we can add together the coefficients except the secret key needs to be
    # rotated too which is where the key switching comes in

    # Let's test out if the key switching rotation works
    output = ciph_prod
    for i in range(1, poly_degree//2):
        rot_key = key_generator.generate_rot_key(i)
        rotated_ciph = evaluator.rotate(ciph_prod, i, rot_key)
        output = evaluator.add(output, rotated_ciph)
    decrypted_prod = decryptor.decrypt(output)
    # print(decrypted_prod)
    # Product will be in the ring
    decoded_prod = encoder.decode(decrypted_prod)

    print(decoded_prod)
    # Now we have the element wise multiplication of all the elements. This is because the convolution in the freq/polynomial
    # multiplication is equivalent to element wise multiplication in the decoded domain. Next, we will do addition
if __name__ == '__main__':
    main()
