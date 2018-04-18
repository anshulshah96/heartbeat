from ..exc import HeartbeatError
from ..util import KeyedPRF
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Util import number


class Challenge(object):
    """The challenge object that represents a challenge posed to the server
    for proof of storage of a file.
    """

    def __init__(self, nonce, key):
        """Initialization method

        :param nonce:
        :param key: the key for this challenge
        """
        self.nonce = nonce
        self.key = key

    def todict(self):
        """Returns a dictionary fully representing the state of this object
        """
        return {"nonce": self.nonce,
                "key": self.key}

    @staticmethod
    def fromdict(dict):
        """Takes a dictionary as an argument and returns a new Challenge
        object from the dictionary.
        """
        pass

    def get_key(self):
        return self.key

class Proof(object):
    """This class encapsulates proof of storage
    """

    def __init__(self):
        """Initialization method"""
        self.mu = list()
        self.sigma = None

    def todict(self):
        """Returns a dictionary fully representing the state of this object
        """
        return {"mu": self.mu,
                "sigma": self.sigma}

    @staticmethod
    def fromdict(dict):
        """Takes a dictionary as an argument and returns a new Proof object
        from the dictionary.

        :param dict: the dictionary to convert
        """
        self = Proof()
        self.mu = dict["mu"]
        self.sigma = dict["sigma"]
        return self


class Golem(object):
    """This class encapsulates the proof of data possession as in
    https://eprint.iacr.org/2008/114.pdf

    """

    def __init__(self, sectorsize=2048, t=10, w=None, z=None, r_perc=50):
        """Initialization method

        :param sectorsize: the size of chunk in bytes
        :param w:
        :param z:
        """
        if w is None:
            self.w = Random.new().read(32)
        else:
            self.w = w

        if z is None:
            self.z = Random.new().read(32)
        else:
            self.z = z
        self.sectorsize = sectorsize
        self.t = t
        self.challenges = list()
        self.verifs = list()
        self.r_perc = r_perc

    def todict(self):
        """Returns a dictionary fully representing the state of this object
        """
        return {"w": self.w,
                "z": self.z,
                "sectorsize": self.sectorsize,
                "t": self.t}

    @staticmethod
    def fromdict(dict):
        """Takes a dictionary as an argument and returns a new PySwizzle
        object from the dictionary.

        :param dict: the dictionary to convert
        """
        return Golem(dict["sectorsize"], dict["w"],
                     dict["z"], dict["t"])

    def get_challenge(self, pos):
        """Gets a public version of the object with the key stripped."""
        return self.challenges[pos]

    def get_verify(self, pos):
        """Gets a public version of the object with the key stripped."""
        return self.verifs[pos]

    def encode(self, file):
        """This function returns a (tag,state) tuple that is calculated for
        the given file.  the state will be encrypted with `self.key`

        :param file: the file to encode
        """

        # state = State(Random.new().read(32), Random.new().read(32))
        PRF_range = 1 << 128
        key_func = KeyedPRF(self.w, PRF_range)
        nonce_func = KeyedPRF(self.z, PRF_range)

        for i in range(self.t):
            nonce = nonce_func.eval(i)
            key = key_func.eval(i)
            chal = Challenge(nonce, key)
            self.challenges.append(chal)

        # alpha = KeyedPRF(state.alpha_key, self.prime)

        done = False
        chunks = list()
        chunk_id = 0
        while not done:
            chunk = file.read(self.sectorsize)
            if len(chunk) == self.sectorsize:
                chunks.append(chunk)
            elif len(chunk) == 0:
                done = True
                break
            elif len(chunk) != self.sectorsize:
                chunks.append(KeyedPRF.pad(chunk, self.sectorsize))
                done = True
            ci = nonce_func.eval(chunk_id)
            ki = key_func.eval(chunk_id)
            chunk_id += 1
            self.challenges.append(Challenge(ci, ki))
        self.num_chunks = chunk_id

        self.r = (self.num_chunks * self.r_perc) // 100
        for i in range(self.t):
            g_func = KeyedPRF(self.challenges[i].key, self.num_chunks)
            pos_array = [g_func.eval(j) for j in range(self.num_chunks)]
            

        return (tag, state)

    def gen_challenge(self, state):
        """This function generates a challenge for given state.  It selects a
        random number and sets that as the challenge key.  By default, v_max
        is set to the prime, and the number of chunks to challenge is the
        number of chunks in the file.  (this doesn't guarantee that the whole
        file will be checked since some chunks could be selected twice and
        some selected none.

        :param state: the state to use.  it can be encrypted, as it will
        have just been received from the server
        """
        state.decrypt(self.key)

        chal = Challenge(state.chunks, self.prime, Random.new().read(32))

        return chal

    def prove(self, file, chal, tag):
        """This function returns a proof calculated from the file, the
        challenge, and the file tag

        :param file: this is a file like object that supports `read()`,
        `tell()` and `seek()` methods.
        :param chal: the challenge to use for proving
        :param tag: the file tag
        """
        chunk_size = self.sectors * self.sectorsize

        index = KeyedPRF(chal.key, len(tag.sigma))
        v = KeyedPRF(chal.key, chal.v_max)

        proof = Proof()
        proof.mu = [0] * self.sectors
        proof.sigma = 0

        for i in range(0, chal.chunks):
            for j in range(0, self.sectors):
                pos = index.eval(i) * chunk_size + j * self.sectorsize
                file.seek(pos)
                buffer = file.read(self.sectorsize)
                if (len(buffer) > 0):
                    proof.mu[j] += v.eval(i) * number.bytes_to_long(buffer)

                if (len(buffer) != self.sectorsize):
                    break

        for j in range(0, self.sectors):
            proof.mu[j] %= self.prime

        for i in range(0, chal.chunks):
            proof.sigma += v.eval(i) * tag.sigma[index.eval(i)]

        proof.sigma %= self.prime

        return proof

    def verify(self, proof, chal, state):
        """This returns True if the proof matches the challenge and file state

        :param proof: the proof that was returned from the server
        :param chal: the challenge sent to the server
        :param state: the state of the file, which can be encrypted
        """
        state.decrypt(self.key)

        index = KeyedPRF(chal.key, state.chunks)
        v = KeyedPRF(chal.key, chal.v_max)
        f = KeyedPRF(state.f_key, self.prime)
        alpha = KeyedPRF(state.alpha_key, self.prime)

        rhs = 0

        for i in range(0, chal.chunks):
            rhs += v.eval(i) * f.eval(index.eval(i))

        for j in range(0, self.sectors):
            rhs += alpha.eval(j) * proof.mu[j]

        rhs %= self.prime
        return proof.sigma == rhs

    @staticmethod
    def tag_type():
        """Returns the type of the tag object associated with this heartbeat
        """
        return Tag

    @staticmethod
    def state_type():
        """Returns the type of the state object associated with this heartbeat
        """
        return State

    @staticmethod
    def challenge_type():
        """Returns the type of the challenge object associated with this
        heartbeat"""
        return Challenge

    @staticmethod
    def proof_type():
        """Returns the type of the proof object associated with this heartbeat
        """
        return Proof
