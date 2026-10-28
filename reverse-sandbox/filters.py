import json

def read_filters(file_path):
    temp = {}
    filters = {}
    with open(file_path) as data:
        temp = json.load(data)

        for key, value in temp.items():
            filters[int(str(key), 16)] = value

    return filters


class Filters(object):

    filters_ios4 = read_filters('filters/filters_ios4.json')
    filters_ios5 = read_filters('filters/filters_ios5.json')
    filters_ios6 = read_filters('filters/filters_ios6.json')
    filters_ios11 = read_filters('filters/filters_ios11.json')
    filters_ios12 = read_filters('filters/filters_ios12.json')
    filters_ios13 = read_filters('filters/filters_ios13.json')
    filters_ios14 = read_filters('filters/filters_ios14.json')

    # iOS 14 is the newest release with a dedicated, validated filter table.
    # iOS 15 through the latest supported release (see LATEST_MAJOR in
    # reverse_sandbox.py) reuse this table as their baseline: Apple has added
    # individual filters since, but the on-disk filter IDs SandBlaster relies
    # on have stayed compatible with the iOS 14 set in practice. Drop a
    # dedicated filters/filters_iosNN.json here and extend get_filters when a
    # newer release is validated against real firmware.
    filters_latest = filters_ios14

    @staticmethod
    def get_filters(ios_major_version):
        if ios_major_version <= 4:
            return Filters.filters_ios4
        if ios_major_version == 5:
            return Filters.filters_ios5
        if ios_major_version == 6:
            return Filters.filters_ios6
        if ios_major_version <= 11:
            return Filters.filters_ios11
        if ios_major_version <= 12:
            return Filters.filters_ios12
        if ios_major_version <= 13:
            return Filters.filters_ios13
        # iOS 14 and every newer release (15 .. 27+) use the latest table.
        return Filters.filters_latest

    @staticmethod
    def exists(ios_major_version, id):
        return id in Filters.get_filters(ios_major_version)

    @staticmethod
    def get(ios_major_version, id):
        return Filters.get_filters(ios_major_version).get(id, None)
