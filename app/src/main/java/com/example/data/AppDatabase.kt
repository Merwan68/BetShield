package com.example.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import com.example.data.dao.BlockEventDao
import com.example.data.dao.BlockedAppDao
import com.example.data.dao.BlockedDomainDao
import com.example.data.dao.SyncMetadataDao
import com.example.data.model.BlockEventEntity
import com.example.data.model.BlockedAppEntity
import com.example.data.model.BlockedDomainEntity
import com.example.data.model.SyncMetadataEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@Database(
    entities = [
        BlockedDomainEntity::class,
        BlockedAppEntity::class,
        BlockEventEntity::class,
        SyncMetadataEntity::class
    ],
    version = 2,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {

    abstract fun blockedDomainDao(): BlockedDomainDao
    abstract fun blockedAppDao(): BlockedAppDao
    abstract fun blockEventDao(): BlockEventDao
    abstract fun syncMetadataDao(): SyncMetadataDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "betshield_database.db"
                )
                    .fallbackToDestructiveMigration(true)
                    .addCallback(DatabasePreloadCallback())
                    .build()
                INSTANCE = instance
                instance
            }
        }

        private class DatabasePreloadCallback : RoomDatabase.Callback() {
            override fun onCreate(db: SupportSQLiteDatabase) {
                super.onCreate(db)
                INSTANCE?.let { database ->
                    CoroutineScope(Dispatchers.IO).launch {
                        try {
                            seedDatabaseIfNeeded(database)
                        } catch (e: Exception) {
                            e.printStackTrace()
                        }
                    }
                }
            }

            override fun onOpen(db: SupportSQLiteDatabase) {
                super.onOpen(db)
                INSTANCE?.let { database ->
                    CoroutineScope(Dispatchers.IO).launch {
                        try {
                            seedDatabaseIfNeeded(database)
                        } catch (e: Exception) {
                            e.printStackTrace()
                        }
                    }
                }
            }

            private suspend fun seedDatabaseIfNeeded(database: AppDatabase) {
                try {
                    val domainDao = database.blockedDomainDao()
                    val appDao = database.blockedAppDao()
                    val metaDao = database.syncMetadataDao()

                    val currentCount = domainDao.getDomainCount()
                    val storedVersion = metaDao.getMetadata("catalog_version")
                        ?.value?.toLongOrNull() ?: 0L

                    if (currentCount == 0 || storedVersion < InitialGamblingCatalog.INITIAL_CATALOG_VERSION) {
                        domainDao.insertDomainsIfAbsent(InitialGamblingCatalog.defaultDomains)
                        appDao.insertAppsIfAbsent(InitialGamblingCatalog.defaultApps)
                        metaDao.upsertMetadata(
                            SyncMetadataEntity(
                                key = "catalog_version",
                                value = InitialGamblingCatalog.INITIAL_CATALOG_VERSION.toString(),
                                updatedAt = System.currentTimeMillis()
                            )
                        )
                        metaDao.upsertMetadata(
                            SyncMetadataEntity(
                                key = "last_synced_at",
                                value = System.currentTimeMillis().toString(),
                                updatedAt = System.currentTimeMillis()
                            )
                        )
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
    }
}
