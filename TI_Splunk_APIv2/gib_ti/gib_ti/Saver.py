import os
import json


class Saver(object):

    def __init__(self, collection, format, data_dir):
        self.format = format
        self.data_dir = data_dir
        self.collection = collection


    def save(self, feeds):
        if self.format == "json":
            self.save_as_json(feeds)
    
    def save_as_json(self, feeds):
        directory = self.data_dir
        if not os.path.exists(directory):
            os.makedirs(directory)
        if len(feeds) != 0:
            with open(os.path.join(directory, str(feeds[0]['seqUpdate']) + ".json" ), "w") as g:
                g.write(json.dumps(feeds))

