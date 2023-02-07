from file_scanner_module import FileScanner
from database_api import HashAPI

# Profiling imports
import cProfile
import pstats

db_location = "database/signatures.db"


# This function isn't finished yet and used for testing purposes, will then be implemented later
def main():
    print("#########################################################################")
    print("# Input a directory to scan and the scanner will start automatically!  #")
    print("# Path syntax: 'C:/Users/someone/Documents/ToScan'                      #")
    print("# REMEMBER! No '/' at the end and no '                                  #")
    print("#########################################################################")
    path_to_check = str(input("Enter path: "))
    print("")
    fs = FileScanner(path_to_check, db_location)
    with cProfile.Profile() as pr:
        fs.start_scanner()

    stats = pstats.Stats(pr)
    stats.sort_stats(pstats.SortKey.TIME)
    #stats.print_stats()
    stats.dump_stats(filename="raspirus_profiling.prof")


def updater():
    hapi = HashAPI(db_location)
    hapi.update_db()
    print(f"Hash amount: {hapi.count_hashes()}")

main()
