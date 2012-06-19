class Parser(object):
    """Base Parser class"""
    def consume(self, tag, message, region):
        raise NotImplementedError("Don't know about tag type %d" % tag.tag_type)

    def only_implemented(self, received, implemented, message):
        if received not in implemented:
            raise NotImplementedError("%s |:| Sorry, haven't implemented value %s. Have only implemented %s." % (self.name, received, message))

    @property
    def name(self):
        return self.__class__.__name__

    def parse_mpi(self, region):
        # Get the length of the MPI to read in
        raw_mpi_length = region.read(2*8).uint
        
        # Read in the MPI bytes and return the resulting bitstream
        mpi_length = (raw_mpi_length + 7) / 8
        return region.read(mpi_length*8)
